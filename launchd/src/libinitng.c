#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <sys/stat.h>
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
static int __initng_sendmsga(int fd, char *command, char *data[], struct cmsghdr *cm, size_t cml);

#define INITNG_SOCKET_ENV       "INITNG_SOCKET"
#define INITNG_SOCKET_DEFAULT   "/var/run/initng.socket"

struct initng_ipc_packet {
	size_t p_len;
	char p_data[0];
};

struct initng_ipc_conn {
	TAILQ_ENTRY(initng_ipc_conn) tqe;
	unsigned int monitoring;
	initng_cred_t cred;
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


int initng_open(void)
{
	struct sockaddr_un sun;
	char *where = getenv(INITNG_SOCKET_ENV);
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, where ? where : INITNG_SOCKET_DEFAULT, sizeof(sun.sun_path));
	
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		close(fd);
		return -1;
	}

	create_ipc_conn(fd);

	return fd;
}

int initng_server_init(const char *thepath)
{
	struct sockaddr_un sun;
	char *where = getenv(INITNG_SOCKET_ENV);
	mode_t oldmask = 0;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, thepath ? thepath : where ? where : INITNG_SOCKET_DEFAULT, sizeof(sun.sun_path));

	if (!thepath && !where)
		oldmask = umask(0);

	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		return -1;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		close(fd);
		return -1;
	}
	if (listen(fd, SOMAXCONN) == -1) {
		close(fd);
		return -1;
	}

	if (!thepath && !where)
		umask(oldmask);

	return fd;
}

int initng_server_accept(int lfd)
{
	struct sockaddr_un sun;
	socklen_t sl = sizeof(sun);
	int cfd;

	if ((cfd = accept(lfd, (struct sockaddr *)&sun, &sl)) == -1)
		return -1;

	create_ipc_conn(cfd);

	return cfd;
}

int initng_flush(int fd)
{
	struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);
	struct cmsghdr *cm;
	struct msghdr mh;
	struct iovec iov;
	int r = 0;

	if (!thisconn) {
		errno = EINVAL;
		return -1;
	}

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

	iov.iov_base = thisconn->sendbuf;
	iov.iov_len = thisconn->sendlen;
	mh.msg_control = thisconn->sendctrllen ? thisconn->sendctrlbuf : NULL;
	mh.msg_controllen = thisconn->sendctrllen;

	if ((r = sendmsg(thisconn->fd, &mh, 0)) == -1)
		return -1;
	else if (r == 0) {
		errno = ECONNRESET;
		return -1;
	}

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

	if (thisconn->sendlen > 0 || thisconn->sendctrllen > 0) {
		errno = EAGAIN;
		return -1;
	}
	
	thisconn->sendbuf = realloc(thisconn->sendbuf, 0);
	thisconn->sendctrlbuf = realloc(thisconn->sendctrlbuf, 0);
	return 0;
}

int initng_recvmsg(int fd, initng_msg_cb cb, void *cookie)
{
        struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);
	struct initng_ipc_packet *p;
        struct msghdr mh;
        struct iovec iov;
	char **datav, *fdstr;
	size_t pl;
        int r;

        if (!thisconn) {
		errno = EINVAL;
                return -1;
        }

        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

	thisconn->recvbuf = realloc(thisconn->recvbuf, thisconn->recvlen + 8*1024);
	thisconn->recvctrlbuf = realloc(thisconn->recvctrlbuf, thisconn->recvlen + 4*1024);

	iov.iov_base = thisconn->recvbuf + thisconn->recvlen;
	iov.iov_len = 8*1024;
	mh.msg_control = thisconn->recvctrlbuf + thisconn->recvctrllen;
	mh.msg_controllen = 4*1024;

	if ((r = recvmsg(thisconn->fd, &mh, 0)) == -1)
		return -1;
	if (r == 0) {
		errno = ECONNRESET;
		return -1;
	}
	if (mh.msg_flags & MSG_CTRUNC) {
		errno = ECONNABORTED;
		return -1;
	}
	thisconn->recvlen += r;
	thisconn->recvctrllen += mh.msg_controllen;

start_over:
	fdstr = NULL;
        p = thisconn->recvbuf;
        if (thisconn->recvlen < sizeof(struct initng_ipc_packet)) {
                errno = EAGAIN;
                return -1;
	}
        if (sizeof(struct initng_ipc_packet) >= p->p_len) {
		errno = ECONNRESET;
		return -1;
	}
        if (thisconn->recvlen < p->p_len) {
                errno = EAGAIN;
                return -1;
	}

	datav = lstring2vdup(p->p_data, p->p_len - sizeof(struct initng_ipc_packet));

	if (strcmp(datav[0], "addFD") == 0) {
		struct cmsghdr *cm = thisconn->recvctrlbuf;
		int cml = CMSG_LEN(sizeof(int));

		if (cm->cmsg_len != cml || cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS) { 
			fprintf(stderr, "bogus ancillary data recieved");
			errno = ECONNRESET;
			return -1;
		}
		asprintf(&fdstr, "%d", *((int*)CMSG_DATA(cm)));
		datav[3] = fdstr;
		memmove(thisconn->recvctrlbuf, thisconn->recvctrlbuf + cml, thisconn->recvctrllen - cml);
        	thisconn->recvctrllen -= cml;
	}

	cb(fd, datav[0], &(datav[1]), cookie, &thisconn->cred);

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
	return 0;
}

int initng_sendmsg(int fd, char *command, ...)
{
	int r;
	va_list ap;
	va_start(ap, command);
	r = initng_sendmsgv(fd, command, ap);
	va_end(ap);
	return r;
}

int initng_msg(int fd, char *command, ...)
{
	int r;
	va_list ap;
	va_start(ap, command);
	r = initng_msgv(fd, command, ap);
	va_end(ap);
	return r;
}

int initng_sendmsgv(int fd, char *command, va_list ap)
{
	int r;
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

int initng_msgv(int fd, char *command, va_list ap)
{
	int r;
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

static int __initng_sendmsga(int fd, char *command, char *data[], struct cmsghdr *cm, size_t cml)
{
	struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);
	char **tmp;
	char *lsa, *lsat;
	size_t lsa_len = strlen(command) + 1;
	struct initng_ipc_packet *p;
#if 0
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(struct cmsgcred))];
	} control_un;

	memset(&control_un, 0, sizeof(control_un));

	control_un.cm.cmsg_len = CMSG_LEN(sizeof(struct cmsgcred));
	control_un.cm.cmsg_type = SCM_CREDS;
#endif

	if (!thisconn) {
		errno = EINVAL;
		return -1;
	}

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

#if 0
	thisconn->sendctrlbuf = realloc(thisconn->sendctrlbuf, thisconn->sendctrllen + sizeof(control_un));
	memcpy(thisconn->sendctrlbuf + thisconn->sendctrllen, &control_un, sizeof(control_un));
	thisconn->sendctrllen += sizeof(control_un);
#endif

	if (cm) {
		thisconn->sendctrlbuf = realloc(thisconn->sendctrlbuf, thisconn->sendctrllen + cml);
		memcpy(thisconn->sendctrlbuf + thisconn->sendctrllen, cm, cml);
		thisconn->sendctrllen += cml;
	}

	return initng_flush(fd);
}

static void simple_msg_cb(int fd __attribute__((unused)), char *command __attribute__((unused)), char *data[], void *cookie, initng_cred_t *cred __attribute__((unused)))
{
	int *r = cookie;
	*r = strtol(data[0], NULL, 10);
	errno = strtol(data[1], NULL, 10);
}

int initng_msga(int fd, char *command, char *data[])
{
	int r;

	if (initng_sendmsga(fd, command, data) == -1)
		return -1;
	if (initng_recvmsg(fd, simple_msg_cb, &r) == -1)
		return -1;
	return r;
}

int initng_sendmsga(int fd, char *command, char *data[])
{
	int r = 0;
	char *tmpa[3] = { data[0], NULL, NULL };
	char *tmp;

	if (strcmp(command, "setUserName") == 0) {
		struct passwd *pwe = getpwnam(data[1]);
		if (!pwe) {
			errno = ENOENT;
			return -1;
		}
		asprintf(&tmp, "%d", pwe->pw_uid);
		tmpa[1] = tmp;
		r = __initng_sendmsga(fd, "setUID", tmpa, NULL, 0);
		free(tmp);
		return r;
	} else if (strcmp(command, "setGroupName") == 0) {
		struct group *gre = getgrnam(data[1]);
		if (!gre) {
			errno = ENOENT;
			return -1;
		}
		asprintf(&tmp, "%d", gre->gr_gid);
		tmpa[1] = tmp;
		r = __initng_sendmsga(fd, "setGID", tmpa, NULL, 0);
		free(tmp);
		return r;
	} else if (strcmp(command, "addUnixSocket") == 0) {
		char *realmsgdata[4] = { data[0], data[1], NULL, NULL };
		struct sockaddr_un sun;
		int socktype;
		bool passive = false;
		int sfd;
		char *fdstr;

		memset(&sun, 0, sizeof(sun));

		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, data[2], sizeof(sun.sun_path));
		if (!strcmp(data[3], "SOCK_STREAM")) {
			socktype = SOCK_STREAM;
		} else if (!strcmp(data[3], "SOCK_DGRAM")) {
			socktype = SOCK_DGRAM;
		} else {
			errno = EINVAL;
			return -1;
		}
		if (!strcmp(data[5], "true"))
			passive = true;

		if ((sfd = socket(AF_UNIX, socktype, 0)) == -1)
			return -1;
		if (passive) {
			if (unlink(sun.sun_path) == -1 && errno != ENOENT) {
				close(sfd);
				return -1;
			}
			if (bind(sfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
				close(sfd);
				return -1;
			}
			if ((socktype == SOCK_STREAM || socktype == SOCK_SEQPACKET)
					&& listen(sfd, SOMAXCONN) == -1) {
				close(sfd);
				return -1;
			}
		} else if (connect(sfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
			close(sfd);
			return -1;
		}

		asprintf(&fdstr, "%d", sfd);
		realmsgdata[2] = fdstr;
		r = initng_sendmsga(fd, "addFD", realmsgdata);
		close(sfd);
		free(fdstr);
		return r;
	} else if (strcmp(command, "addGetaddrinfoSockets") == 0) {
		char *realmsgdata[4] = { data[0], data[1], NULL, NULL };
		struct addrinfo hints, *res, *res0 = NULL;
		int sfd;
		char *n = NULL, *s = NULL;
		char *fdstr;

		/* addGetaddrinfoSockets
		 *
		 * joblabel, socklabel, socknodename, sockservname, sockfamily,
		 * socktype, sockprotocol, sockpassive, NULL
		 */
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

		if (getaddrinfo(n, s, &hints, &res0)) {
			errno = ENOENT;
			return -1;
		}

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
			if (res->ai_next)
				r = initng_msga(fd, "addFD", realmsgdata);
			else
				r = initng_sendmsga(fd, "addFD", realmsgdata);
			close(sfd);
			free(fdstr);
			if (r == -1)
				goto res_walk_out_bad;
			if (hints.ai_flags & AI_PASSIVE)
				continue;
			else
				break;
res_walk_out_bad:
			freeaddrinfo(res0);
			return -1;
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
	} else {
		return __initng_sendmsga(fd, command, data, NULL, 0);
	}
}

int initng_fdcheckin(initng_fdcheckin_cb cb, void *cookie)
{
	char *fds = getenv("__INITNG_FDS");
	char fdlabelkey[128];
	char *fdlabel, *endptr;
	int fd;

	if (!fds) {
		errno = ESRCH;
		return -1;
	}

	while (*fds != '\0') {
		fd = strtol(fds, &endptr, 10);
		sprintf(fdlabelkey, "__INITNG_FD_%d", fd);
		fdlabel = getenv(fdlabelkey);
		cb(fd, fdlabel, cookie);
		fds = endptr;
	}
	return 0;
}

static void create_ipc_conn(int fd)
{
        struct initng_ipc_conn *c;
	struct xucred cr;
	int crlen = sizeof(cr);

        c = calloc(1, sizeof(struct initng_ipc_conn));
        c->fd = fd;
        c->sendbuf = malloc(0);
        c->sendctrlbuf = malloc(0);
        c->recvbuf = malloc(0);
        c->recvctrlbuf = malloc(0);

	if (getsockopt(fd,  LOCAL_PEERCRED, 1, &cr, &crlen) == -1) {
		c->cred.ic_uid = -1;
		c->cred.ic_gid = -1;
	} else {
		c->cred.ic_uid = cr.cr_uid;
		c->cred.ic_gid = cr.cr_groups[0];
	}

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

int initng_close(int fd)
{
	struct initng_ipc_conn *thisconn = find_conn_with_fd(fd);

	if (!thisconn) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_REMOVE(&theconnections, thisconn, tqe);
	free(thisconn->sendbuf);
	free(thisconn->sendctrlbuf);
	free(thisconn->recvbuf);
	free(thisconn->recvctrlbuf);
	close(thisconn->fd);
	free(thisconn);

	return 0;
}

static char **lstring2vdup(char *data, size_t data_len)
{
        char *lastseenstring = NULL;
        char **r;
        size_t argc = 0;
        unsigned int i, j = 0;

        for (i = 0; i < data_len; i++) {
                if (data[i] == '\0')
                        argc++;
        }
        r = malloc((argc * sizeof(char*)) + 1);
        r[argc] = NULL;
        lastseenstring = data;
        for (i = 0; i < data_len; i++) {
                if (data[i] == '\0') {
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

	TAILQ_FOREACH(var, &theconnections, tqe) {
		if (var->monitoring) {
			if (initng_sendmsga(var->fd, command, data) == -1)
				fprintf(stderr, "broadcast burp\n");
		}
	}
}
