#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#define INITNG_PRIVATE_API
#include "libinitng.h"

static struct initng_ipc_conn *find_conn_with_fd(int fd);
static void create_ipc_conn(int fd);
static char **lstring2vdup(char *data, size_t data_len);
static initng_err_t __initng_sendmsga(int fd, char *command, char *data[], struct cmsghdr *cm, size_t cml);

#define INITNG_SOCKET_ENV       "INITNG_SOCKET"
#define INITNG_SOCKET_DEFAULT   "/var/run/initng.socket"

struct initng_ipc_packet {
	size_t p_len;
	char p_data[0];
};

struct initng_ipc_conn {
	TAILQ_ENTRY(initng_ipc_conn) tqe;
	unsigned int monitoring;
	int     fd;
	void    *sendbuf;
	size_t  sendlen;
	void    *sendctrlbuf;
	size_t  sendctrllen;
	void    *recvbuf;
	size_t  recvlen;
	void    *recvctrlbuf;
	size_t  recvctrllen;
};

static TAILQ_HEAD(initng_ipc_connections, initng_ipc_conn) theconnections = TAILQ_HEAD_INITIALIZER(theconnections);

initng_err_t initng_init(int *fd, const char *thepath)
{
	struct sockaddr_un sun;
	char *where = getenv(INITNG_SOCKET_ENV);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, thepath ? thepath : where ? where : INITNG_SOCKET_DEFAULT, sizeof(sun.sun_path));
	
	if ((*fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return INITNG_ERR_SYSCALL;
	if (connect(*fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		close(*fd);
		return INITNG_ERR_SYSCALL;
	}

	create_ipc_conn(*fd);

	return INITNG_ERR_SUCCESS;
}

initng_err_t initng_server_init(int *fd, const char *thepath)
{
	struct sockaddr_un sun;
	char *where = getenv(INITNG_SOCKET_ENV);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, thepath ? thepath : where ? where : INITNG_SOCKET_DEFAULT, sizeof(sun.sun_path));

        if (unlink(sun.sun_path) == -1 && errno != ENOENT)
                return INITNG_ERR_SYSCALL;
	if ((*fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
                return INITNG_ERR_SYSCALL;
        if (bind(*fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		close(*fd);
                return INITNG_ERR_SYSCALL;
	}
        if (listen(*fd, 255) == -1) {
		close(*fd);
                return INITNG_ERR_SYSCALL;
	}

        return INITNG_ERR_SUCCESS;
}

initng_err_t initng_server_accept(int *cfd, int lfd)
{
        struct sockaddr_un sun;
        socklen_t sl = sizeof(sun);

        if ((*cfd = accept(lfd, (struct sockaddr *)&sun, &sl)) == -1)
                return INITNG_ERR_SYSCALL;

	create_ipc_conn(*cfd);

	return INITNG_ERR_SUCCESS;
}

initng_err_t initng_flush(int fd)
{
        struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);
	struct cmsghdr *cm;
        struct msghdr mh;
        struct iovec iov;
        int r;

        if (!thisconn) {
                return INITNG_ERR_CONN_NOT_FOUND;
        }

        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

	iov.iov_base = thisconn->sendbuf;
	iov.iov_len = thisconn->sendlen;
	mh.msg_control = thisconn->sendctrllen ? thisconn->sendctrlbuf : NULL;
	mh.msg_controllen = thisconn->sendctrllen;

	if ((r = sendmsg(thisconn->fd, &mh, 0)) == -1)
		return INITNG_ERR_SYSCALL;
	if (r == 0)
		return INITNG_ERR_BROKEN_CONN;

	memmove(thisconn->sendbuf, thisconn->sendbuf + r, r);
	thisconn->sendlen -= r;

	while (mh.msg_controllen > 0) {
		cm = thisconn->sendctrlbuf;
		if (cm->cmsg_len == CMSG_LEN(sizeof(int)) &&
				cm->cmsg_level == SOL_SOCKET &&
				cm->cmsg_type == SCM_RIGHTS)
	                close(*((int*)CMSG_DATA(cm)));
		mh.msg_controllen -= cm->cmsg_len;
		thisconn->sendctrllen -= cm->cmsg_len;
		memmove(thisconn->sendctrlbuf, thisconn->sendctrlbuf + cm->cmsg_len, cm->cmsg_len);
	}

	if (thisconn->sendlen > 0 || thisconn->sendctrllen > 0)
		return INITNG_ERR_AGAIN;
	
	thisconn->sendbuf = realloc(thisconn->sendbuf, 0);
	thisconn->sendctrlbuf = realloc(thisconn->sendctrlbuf, 0);
	return INITNG_ERR_SUCCESS;
}

initng_err_t initng_recvmsg(int fd, initng_msg_cb cb, void *cookie)
{
        struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);
	struct initng_ipc_packet *p;
        struct msghdr mh;
        struct iovec iov;
	char **datav, *fdstr;
	size_t pl;
        int r;

        if (!thisconn) {
                return INITNG_ERR_CONN_NOT_FOUND;
        }

        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

	thisconn->recvbuf = realloc(thisconn->recvbuf, thisconn->recvlen + 16*1024);
	thisconn->recvctrlbuf = realloc(thisconn->recvctrlbuf, thisconn->recvlen + 4*1024);

	iov.iov_base = thisconn->recvbuf + thisconn->recvlen;
	iov.iov_len = 16*1024;
	mh.msg_control = thisconn->recvctrlbuf + thisconn->recvctrllen;
	mh.msg_controllen = 4*1024;

	if ((r = recvmsg(thisconn->fd, &mh, 0)) == -1)
		return INITNG_ERR_SYSCALL;
	if (r == 0)
		return INITNG_ERR_BROKEN_CONN;
	if (mh.msg_flags & MSG_CTRUNC)
		return INITNG_ERR_RECVMSG_CTRUNC;
	thisconn->recvlen += r;
	thisconn->recvctrllen += mh.msg_controllen;

start_over:
	fdstr = NULL;
        p = thisconn->recvbuf;
        if (thisconn->recvlen < sizeof(struct initng_ipc_packet))
                return INITNG_ERR_AGAIN;
        if (sizeof(struct initng_ipc_packet) >= p->p_len)
		return INITNG_ERR_BROKEN_CONN;
        if (thisconn->recvlen < p->p_len)
                return INITNG_ERR_AGAIN;

	datav = lstring2vdup(p->p_data, p->p_len - sizeof(struct initng_ipc_packet));

	if (strcmp(datav[0], "addFD") == 0) {
		struct cmsghdr *cm = thisconn->recvctrlbuf;
		int cml = CMSG_LEN(sizeof(int));

		if (cm->cmsg_len != cml || cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS) { 
			fprintf(stderr, "bogus ancillary data recieved");
			return INITNG_ERR_BROKEN_CONN;
		}
		asprintf(&fdstr, "%d", *((int*)CMSG_DATA(cm)));
		datav[3] = fdstr;
		memmove(thisconn->recvctrlbuf, thisconn->recvctrlbuf + cml, thisconn->recvctrllen - cml);
        	thisconn->recvctrllen -= cml;
	}

	cb(fd, datav[0], &(datav[1]), cookie);

	if (fdstr)
		free(fdstr);
	free(datav);

	pl = p->p_len;
	memmove(thisconn->recvbuf, thisconn->recvbuf + pl, thisconn->recvlen - pl);
        thisconn->recvlen -= pl;

	if (thisconn->recvlen > 0)
		goto start_over;

	thisconn->recvbuf = realloc(thisconn->recvbuf, 0);
        if (thisconn->recvctrllen == 0)
		thisconn->recvctrlbuf = realloc(thisconn->recvctrlbuf, 0);
	return INITNG_ERR_SUCCESS;
}

initng_err_t initng_sendmsg(int fd, char *command, ...)
{
	initng_err_t r;
	va_list ap;
	va_start(ap, command);
	r = initng_sendmsgv(fd, command, ap);
	va_end(ap);
	return r;
}

initng_err_t initng_msg(int fd, char *command, ...)
{
	initng_err_t r;
	va_list ap;
	va_start(ap, command);
	r = initng_msgv(fd, command, ap);
	va_end(ap);
	return r;
}

initng_err_t initng_sendmsgv(int fd, char *command, va_list ap)
{
	initng_err_t r;
	va_list origap = ap;
	size_t c = 0;
	char **v, **vt;
	while (va_arg(ap, char*))
		c++;
	ap = origap;
	v = vt = malloc((c + 1) * sizeof(char*));
	v[c] = NULL;
	while ((*vt = va_arg(ap, char *)))
		vt++;
	r = initng_sendmsga(fd, command, v);
	free(v);
	return r;
}

initng_err_t initng_msgv(int fd, char *command, va_list ap)
{
	initng_err_t r;
	va_list origap = ap;
	size_t c = 0;
	char **v, **vt;
	while (va_arg(ap, char*))
		c++;
	ap = origap;
	v = vt = malloc((c + 1) * sizeof(char*));
	v[c] = NULL;
	while ((*vt = va_arg(ap, char *)))
		vt++;
	r = initng_msga(fd, command, v);
	free(v);
	return r;
}

static initng_err_t __initng_sendmsga(int fd, char *command, char *data[], struct cmsghdr *cm, size_t cml)
{
	struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);
	char **tmp;
	char *lsa, *lsat;
	size_t lsa_len = strlen(command) + 1;
	struct initng_ipc_packet *p;

	if (!thisconn)
		return INITNG_ERR_CONN_NOT_FOUND;

	for (tmp = data; *tmp; tmp++)
		lsa_len += strlen(*tmp) + 1;

	p = malloc(lsa_len + sizeof(struct initng_ipc_packet));
	p->p_len = sizeof(p) + lsa_len;
	lsa = lsat = p->p_data;

	strcpy(lsat, command);
	lsat += strlen(command) + 1;
	for (tmp = data; *tmp; tmp++) {
		strcpy(lsat, *tmp);
		lsat += strlen(*tmp) + 1;
	}

	thisconn->sendbuf = realloc(thisconn->sendbuf, thisconn->sendlen + p->p_len);
	memcpy(thisconn->sendbuf + thisconn->sendlen, p, p->p_len);
	thisconn->sendlen += p->p_len;
	free(p);

	if (cm) {
		thisconn->sendctrlbuf = realloc(thisconn->sendctrlbuf, thisconn->sendctrllen + cml);
		memcpy(thisconn->sendctrlbuf + thisconn->sendctrllen, cm, cml);
		thisconn->sendctrllen += cml;
	}

	return initng_flush(fd);
}

static void simple_msg_cb(int fd, char *command, char *data[], void *cookie)
{
	char **r = cookie;
	*r = strdup(*data);
}

initng_err_t initng_msga(int fd, char *command, char *data[])
{
	initng_err_t ingerr;
	char *result = NULL;

	ingerr = initng_sendmsga(fd, command, data);
	if (ingerr != INITNG_ERR_SUCCESS)
		goto out;
	ingerr = initng_recvmsg(fd, simple_msg_cb, &result);
	if (ingerr != INITNG_ERR_SUCCESS)
		goto out;
	if (!strcmp(result, "success"))
		ingerr = INITNG_ERR_SUCCESS;
	else {
		ingerr = -1;
		fprintf(stderr, "d'oh: %s\n", result);
	}
out:
	if (result)
		free(result);
	return ingerr;
}

initng_err_t initng_sendmsga(int fd, char *command, char *data[])
{
	initng_err_t r = INITNG_ERR_SUCCESS;
	char *tmpa[3] = { data[0], NULL, NULL };
	char *tmp;

	if (strcmp(command, "setUserName") == 0) {
		struct passwd *pwe = getpwnam(data[1]);
		if (!pwe)
			return INITNG_ERR_DIRECTORY_LOOKUP;
		asprintf(&tmp, "%d", pwe->pw_uid);
		tmpa[1] = tmp;
		r = __initng_sendmsga(fd, "setUID", tmpa, NULL, 0);
		free(tmp);
		return r;
	} else if (strcmp(command, "setGroupName") == 0) {
		struct group *gre = getgrnam(data[1]);
		if (!gre)
			return INITNG_ERR_DIRECTORY_LOOKUP;
		asprintf(&tmp, "%d", gre->gr_gid);
		tmpa[1] = tmp;
		r = __initng_sendmsga(fd, "setGID", tmpa, NULL, 0);
		free(tmp);
		return r;
	} else if (strcmp(command, "addGetaddrinfoSockets") == 0) {
		struct addrinfo hints, *res, *res0 = NULL;
		int sfd;
		char *n = NULL, *s = NULL;
		char *realmsgdata[4];
		char *fdstr;

		/* addGetaddrinfoSockets
		 *
		 * joblabel, socklabel, socknodename, sockservname, sockfamily,
		 * socktype, sockprotocol, sockpassive, NULL
		 */
		                
		/* XXX - sort out arguments */
		memset(&hints, 0, sizeof(hints));
		if (strlen(data[2]) > 0)	/* nodename */
			n = data[2];
		if (strlen(data[3]) > 0)	/* servname */
			s = data[3];
		if (strlen(data[4]) > 0)	/* family */
			fprintf(stderr, "family parsing not yet implemented\n");
		if (strlen(data[5]) > 0) {	/* socktype */
			if (!strcmp(data[5], "SOCK_STREAM"))
				hints.ai_socktype = SOCK_STREAM;
			else if (!strcmp(data[5], "SOCK_DGRAM"))
				hints.ai_socktype = SOCK_DGRAM;
			else
				fprintf(stderr, "unknown socket type\n");
		}
		if (strlen(data[6]) > 0)	/* protocol */
			fprintf(stderr, "protocol parsing not yet implemented\n");
		if (strlen(data[7]) > 0) {	/* passive */
			if (!strcmp(data[7], "true"))
				hints.ai_flags |= AI_PASSIVE;
		}

		if (getaddrinfo(n, s, &hints, &res0))
			return INITNG_ERR_DIRECTORY_LOOKUP;

		realmsgdata[0] = data[0];
		realmsgdata[1] = data[1];
		realmsgdata[3] = NULL;

		for (res = res0; res; res = res->ai_next) {
			int sock_opt = 1;
			if ((sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
				goto res_walk_out_bad;
			if (hints.ai_flags & AI_PASSIVE) {
				if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt, sizeof(sock_opt)) == -1)
					goto res_walk_out_bad;
			       	if (bind(sfd, res->ai_addr, res->ai_addrlen) == -1)
					goto res_walk_out_bad;
				if ((res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_SEQPACKET)
						&& listen(sfd, SOMAXCONN) == -1)
					goto res_walk_out_bad;
			} else {
				if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					if (res->ai_next) {
						close(sfd);
						continue;
					} else
						goto res_walk_out_bad;
				}
			}
			asprintf(&fdstr, "%d", sfd);
			realmsgdata[2] = fdstr;
			r = initng_sendmsga(fd, "addFD", realmsgdata);
			close(sfd);
			free(fdstr);
			if (r != INITNG_ERR_SUCCESS)
				goto res_walk_out_bad;
			if (hints.ai_flags & AI_PASSIVE)
				continue;
			else
				break;
res_walk_out_bad:
			freeaddrinfo(res0);
			return INITNG_ERR_SYSCALL;
		}

		freeaddrinfo(res0);
		return r;
	} else if (strcmp(command, "addFD") == 0) {
		union {
			struct cmsghdr cm;
			char control[CMSG_SPACE(sizeof(int))];
		} control_un;

		control_un.cm.cmsg_len = CMSG_LEN(sizeof(int));
		control_un.cm.cmsg_level = SOL_SOCKET;
		control_un.cm.cmsg_type = SCM_RIGHTS;

		*((int*)CMSG_DATA(&control_un.cm)) = dup(strtol(data[2], NULL, 10));

		return __initng_sendmsga(fd, command, data, &(control_un.cm), sizeof(control_un));
	}
	return __initng_sendmsga(fd, command, data, NULL, 0);
}

struct __resultmgmt {
	bool done;
	size_t config_size;
	char ***config;
};

static void config_msg_cb(int fd, char *command, char *data[], void *cookie)
{
	struct __resultmgmt *__resultmgmt = cookie;
	char **r, **t;
	int s = 1;

	if (!strcmp(command, "dumpJobStateDONE")) {
		__resultmgmt->done = true;
		return;
	}

	__resultmgmt->config_size++;
	__resultmgmt->config = realloc(__resultmgmt->config, __resultmgmt->config_size * sizeof(char***));

	for (t = data; *t; t++)
		s++;
	r = malloc((s + 1) * sizeof(char*));
	r[s] = NULL;
	r[0] = strdup(command);
	for (s = 1, t = data; *t; t++, s++)
		r[s] = strdup(*t);
	__resultmgmt->config[__resultmgmt->config_size - 2] = r;
	__resultmgmt->config[__resultmgmt->config_size - 1] = NULL;
}

void initng_freeconfig(char ***config)
{
	char **tmpv, ***tmpvv;

	for (tmpvv = config; *tmpvv; tmpvv++) {
		for (tmpv = *tmpvv; *tmpv; tmpv++)
			free(*tmpv);
		free(*tmpvv);
	}
	free(config);
}

initng_err_t initng_checkin(int fd, char ****config)
{
	initng_err_t ingerr = INITNG_ERR_SUCCESS;
	char *jl = getenv("INITNG_JOB_LABEL");
	struct __resultmgmt __resultmgmt;

	__resultmgmt.done = false;
	__resultmgmt.config_size = 1;
	__resultmgmt.config = malloc(sizeof(char***));
	__resultmgmt.config[0] = NULL;


	*config = NULL;

	if (!jl)
		return INITNG_ERR_BROKEN_CONN;

	ingerr = initng_sendmsg(fd, "dumpJobState", jl, NULL);
	if (ingerr != INITNG_ERR_SUCCESS)
		return ingerr;
	while (__resultmgmt.done != true) {
		ingerr = initng_recvmsg(fd, config_msg_cb, &__resultmgmt);
		if (ingerr != INITNG_ERR_SUCCESS)
			return ingerr;
	}

	*config = __resultmgmt.config;
	return ingerr;
}

static void create_ipc_conn(int fd)
{
        struct initng_ipc_conn *c;

        c = calloc(1, sizeof(struct initng_ipc_conn));
        c->fd = fd;
        c->sendbuf = malloc(0);
        c->sendctrlbuf = malloc(0);
        c->recvbuf = malloc(0);
        c->recvctrlbuf = malloc(0);
        TAILQ_INSERT_TAIL(&theconnections, c, tqe);
}

static struct initng_ipc_conn *find_conn_with_fd(int fd)
{
	struct initng_ipc_conn *var;
	TAILQ_FOREACH(var, &theconnections, tqe) {
		if (var->fd == fd)
			return var;
	}
	return NULL;
}

initng_err_t initng_close(int fd)
{
	struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);

	if (!thisconn)
		return INITNG_ERR_CONN_NOT_FOUND;

	TAILQ_REMOVE(&theconnections, thisconn, tqe);
	free(thisconn->sendbuf);
	free(thisconn->sendctrlbuf);
	free(thisconn->recvbuf);
	free(thisconn->recvctrlbuf);
	close(thisconn->fd);
	free(thisconn);

	return INITNG_ERR_SUCCESS;
}

const char *initng_strerror(initng_err_t error)
{
	const char *const errs[] = {
		[INITNG_ERR_SUCCESS] =		"Success",
		[INITNG_ERR_AGAIN] =		"Resource temporarily unavailable",
		[INITNG_ERR_CONN_NOT_FOUND] =	"Connection for FD not found",
		[INITNG_ERR_SYSCALL] =		"System call failure",
		[INITNG_ERR_RECVMSG_CTRUNC] =	"Whoops, we underbudgeted the ancillary data buffer size",
		[INITNG_ERR_DIRECTORY_LOOKUP] =	"Directory lookup failure",
		[INITNG_ERR_BROKEN_CONN] =	"The connection broke",
	};

	if (error >= (sizeof(errs) / sizeof(char *)) || errs[error] == NULL) {
		return "Unknown initng error";
	}
	if (error == INITNG_ERR_SYSCALL)
		fprintf(stderr, "INITNG_ERR_SYSCALL: %s\n", strerror(errno));
	return errs[error];
}

static char **lstring2vdup(char *data, size_t data_len)
{
        char *lastseenstring = NULL;
        char **r;
        size_t argc = 0;
        unsigned int i, j = 0;

        for (i = 0; i < data_len; i++) {
                if (data[i] == NULL)
                        argc++;
        }
        r = malloc((argc * sizeof(char*)) + 1);
        r[argc] = NULL;
        lastseenstring = data;
        for (i = 0; i < data_len; i++) {
                if (data[i] == NULL) {
                        r[j] = lastseenstring;
                        j++;
                        lastseenstring = &(data[i]) + 1;
                }
        }
        return r;
}

void initng_set_sniffer(int fd, bool e)
{
        struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);

	if (thisconn)
		thisconn->monitoring = e;
}

void initng_sendmsga2sniffers(char *command, char *data[])
{
	struct initng_ipc_conn *var;
	initng_err_t ingerr;
	TAILQ_FOREACH(var, &theconnections, tqe) {
		if (var->monitoring) {
			ingerr = initng_sendmsga(var->fd, command, data);
			if (ingerr != INITNG_ERR_SUCCESS)
				fprintf(stderr, "broadcast burp\n");
		}
	}
}
