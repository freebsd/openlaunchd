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
#include "libinitng.h"
#include "initngd.h"

static bool initng_jobinfo_set_data(initng_jobinfo_t j, void *d, size_t dl, int command);
static bool initng_jobinfo_set_data_with_ancillary(initng_jobinfo_t j, void *d, size_t dl, int command, void *c, size_t cl);
static bool initng_jobinfo_set_string(initng_jobinfo_t j, char *s, int command);
static bool initng_jobinfo_set_multiple_strings(initng_jobinfo_t j, char *sa[], int command);

struct initng_jobinfo {
	char uuid[16];
};

static int initng_fd;

int initng_init(void)
{
	struct sockaddr_un sun;
	char *where;
	int r = 0;
	
	where = getenv(INITNG_SOCKET_ENV);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, where ? where : INITNG_SOCKET_DEFAULT, sizeof(sun.sun_path));
	
	initng_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (initng_fd == -1)
		return -1;
	r = connect(initng_fd, (struct sockaddr *)&sun, sizeof(sun));
	if (r == -1)
		return -1;
	return initng_fd;
}

bool initng_jobinfo_alloc(initng_jobinfo_t *j, char *u)
{
	bool r;

	*j = calloc(1, sizeof(struct initng_jobinfo));
	memcpy((*j)->uuid, u, 16);

	r = initng_jobinfo_set_data(*j, NULL, 0, INITNG_CREATE);
	if (!r)
		free(*j);
	return r;
}

void initng_jobinfo_free(initng_jobinfo_t j)
{
	free(j);
}

bool initng_jobinfo_set_UserName(initng_jobinfo_t j, char *u)
{
	struct passwd *pwe = getpwnam(u);

	if (!pwe)
		return false;

	return initng_jobinfo_set_data(j, &pwe->pw_uid, sizeof(uid_t), INITNG_SET_UID);
}

bool initng_jobinfo_set_GroupName(initng_jobinfo_t j, char *g)
{
	struct group *gre = getgrnam(g);

	if (!gre)
		return false;

	return initng_jobinfo_set_data(j, &gre->gr_gid, sizeof(gid_t), INITNG_SET_GID);
}

bool initng_jobinfo_set_EnvironmentVariables(initng_jobinfo_t j, char *envp[])
{
	return initng_jobinfo_set_multiple_strings(j, envp, INITNG_SET_ENV);
}

bool initng_jobinfo_set_Enabled(initng_jobinfo_t j, bool e)
{
	return initng_jobinfo_set_data(j, &e, sizeof(bool), INITNG_SET_FLAG_ENABLED);
}

bool initng_jobinfo_set_LaunchOnce(initng_jobinfo_t j, bool lo)
{
	return initng_jobinfo_set_data(j, &lo, sizeof(bool), INITNG_SET_FLAG_LAUNCH_ONCE);
}

bool initng_jobinfo_set_OnDemand(initng_jobinfo_t j, bool od)
{
	return initng_jobinfo_set_data(j, &od, sizeof(bool), INITNG_SET_FLAG_ON_DEMAND);
}

bool initng_jobinfo_set_Batch(initng_jobinfo_t j, bool b)
{
	return initng_jobinfo_set_data(j, &b, sizeof(bool), INITNG_SET_FLAG_BATCH);
}

bool initng_jobinfo_set_ServiceIPC(initng_jobinfo_t j, bool sipc)
{
	return initng_jobinfo_set_data(j, &sipc, sizeof(bool), INITNG_SET_FLAG_SUPPORTS_MGMT);
}

bool initng_jobinfo_set_inetdSingleThreaded(initng_jobinfo_t j, bool st)
{
	return initng_jobinfo_set_data(j, &st, sizeof(bool), INITNG_SET_FLAG_INETD_SINGLE_THREADED);
}

bool initng_jobinfo_set_PeriodicSeconds(initng_jobinfo_t j, unsigned int ps)
{
	return initng_jobinfo_set_data(j, &ps, sizeof(ps), INITNG_SET_PERIODIC);
}

bool initng_jobinfo_set_Program(initng_jobinfo_t j, char *pr)
{
	return initng_jobinfo_set_string(j, pr, INITNG_SET_PROGRAM);
}

bool initng_jobinfo_set_ProgramArguments(initng_jobinfo_t j, char *argv[])
{
	return initng_jobinfo_set_multiple_strings(j, argv, INITNG_SET_ARGV);
}

bool initng_jobinfo_set_ServiceDescription(initng_jobinfo_t j, char *sd)
{
	return initng_jobinfo_set_string(j, sd, INITNG_SET_DESCRIPTION);
}

bool initng_jobinfo_set_MachServiceNames(initng_jobinfo_t j, char *msn[])
{
	return initng_jobinfo_set_multiple_strings(j, msn, INITNG_SET_MACH_SERVICE_NAMES);
}

bool initng_jobinfo_add_Socket(initng_jobinfo_t j, struct addrinfopp *ai)
{
	struct addrinfo *res, *res0 = NULL;
	int fd;
	int error;
	bool r = false;
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;

	error = getaddrinfo(ai->nodename, ai->servname, &ai->hints, &res0);
	if (error) {
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
		if (res0)
			goto out;
		return false;
	}

	for (res = res0; res; res = res->ai_next) {
		if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
			goto out;
		}
		if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
			close(fd);
			goto out;
		}
		if ((res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_SEQPACKET)
				&& listen(fd, SOMAXCONN) == -1) {
			close(fd);
			goto out;
		}
		control_un.cm.cmsg_len = CMSG_LEN(sizeof(int));
		control_un.cm.cmsg_level = SOL_SOCKET;
		control_un.cm.cmsg_type = SCM_RIGHTS;
		*((int*)CMSG_DATA(&control_un.cm)) = fd;
		r = initng_jobinfo_set_data_with_ancillary(j, ai, sizeof(struct addrinfopp), INITNG_ADD_FD,
				&control_un, sizeof(control_un));
		close(fd);
		if (r == false)
			goto out;
	}
out:
	freeaddrinfo(res0);
	return r;
}

static bool initng_jobinfo_set_string(initng_jobinfo_t j, char *s, int command)
{
	return initng_jobinfo_set_data(j, s, strlen(s) + 1, command);
}

static bool initng_jobinfo_set_data(initng_jobinfo_t j, void *d, size_t dl, int command)
{
	return initng_jobinfo_set_data_with_ancillary(j, d, dl, command, NULL, 0);
}

static bool initng_jobinfo_set_data_with_ancillary(initng_jobinfo_t j, void *d, size_t dl, int command, void *c, size_t cl)
{
	struct msghdr mh;
	struct initng_ipc_packet p;
	struct iovec iov[2] = { { (void*)&p, sizeof(p) }, { d, dl } };
	ssize_t wr, rr;

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = iov;
	mh.msg_iovlen = 2;
	mh.msg_control = c;
	mh.msg_controllen = cl;

	p.version = INITNG_PROTOCOL_VERSION;
	p.command = command;
	memcpy(&p.uuid, j->uuid, 16);
	p.data_len = dl;

	if ((wr = sendmsg(initng_fd, &mh, 0)) != (ssize_t)(sizeof(p) + dl)) {
		fprintf(stderr, "sendmsg(): %s\n", strerror(errno));
		return false;
	}
	if ((rr = read(initng_fd, &p, sizeof(p))) != (ssize_t)sizeof(p)) {
		fprintf(stderr, "read(): %s\n", strerror(errno));
		return false;
	}
	if (p.return_code == 0)
		return true;
	else
		return false;
}

static bool initng_jobinfo_set_multiple_strings(initng_jobinfo_t j, char *sa[], int command)
{
	char *lsa, *lsat;
	size_t lsa_len = 0;
	char **tmp;
	bool r;

	for (tmp = sa; *tmp; tmp++)
		lsa_len += strlen(*tmp) + 1;

	lsa = lsat = malloc(lsa_len);

	for (tmp = sa; *tmp; tmp++) {
		strcpy(lsat, *tmp);
		lsat += strlen(*tmp) + 1;
	}

	r = initng_jobinfo_set_data(j, lsa, lsa_len, command);
	free(lsa);
	return r;
}
