#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>

#include "initngd_private.h"

extern char **environ;

#define JOB_ENABLED		0x00000001
#define JOB_ON_DEMAND		0x00000002
#define JOB_BATCH		0x00000004
#define JOB_LAUNCH_ONCE		0x00000008
#define JOB_SUPPORTS_MGMT	0x00000010
#define JOB_RUNNING		0x00000020
#define JOB_INETD_ST		0x00000040

struct initng_job_fd {
	TAILQ_ENTRY(initng_job_fd) tqe;
	int fd;
	void *data;
	size_t data_len;
};

struct initng_job {
	TAILQ_ENTRY(initng_job) tqe;
	char uuid[16];
	uid_t u;
	gid_t g;
	char *description;
	char *program;
	char **argv;
	char **env;
	char **msn;
	unsigned int periodic;
	int flags;
	TAILQ_HEAD(initng_job_fds, initng_job_fd) thefds;
	struct initng_ipc_conn *trusted_conn;
	pid_t p;
};

TAILQ_HEAD(initng_jobs, initng_job) thejobs = TAILQ_HEAD_INITIALIZER(thejobs);

struct initng_ipc_conn {
	TAILQ_ENTRY(initng_ipc_conn) tqe;
	int	fd;
	void	*sendbuf;
	size_t	sendlen;
	void	*sendctrlbuf;
	size_t	sendctrllen;
	void	*recvbuf;
	size_t	recvlen;
	void	*recvctrlbuf;
	size_t	recvctrllen;
};

TAILQ_HEAD(initng_ipc_connections, initng_ipc_conn) theconnections = TAILQ_HEAD_INITIALIZER(theconnections);

static int thesocket = 0;
static int kq = 0;
static char *argv0 = NULL;

static void initsocket(const char *thepath);
static void therunloop(void) __attribute__((noreturn));
static void do_accept_logic(void);
static void handle_event(struct kevent *kev);
static void do_ipc_logic(struct kevent *kev);
static struct initng_ipc_conn *create_ipc_conn(int fd);
static void initngd_debug(int priority, const char *format, ...) __attribute__((format(printf,2,3)));
static void initngd_panic(const char *format, ...) __attribute__((noreturn, format(printf,1,2)));
static int kevent_add_one(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);
static struct initng_ipc_conn *find_conn_with_fd(int fd);
static void close_ipc_conn(struct initng_ipc_conn *conn);
static void parse_packets(struct initng_ipc_conn *thisconn);
static void usage(FILE *where) __attribute__((noreturn));
static void launch_job(struct initng_job *j);
static void launch_job_st(struct initng_job *j);
static void reap_job(struct initng_job *j);
static void runloop_observe(struct initng_job *j);
static void runloop_ignore(struct initng_job *j);
static int job_create(struct initng_ipc_packet *p);
static int job_remove(struct initng_ipc_packet *p);
static int job_set_uid(struct initng_ipc_packet *p);
static int job_set_gid(struct initng_ipc_packet *p);
static int job_set_program(struct initng_ipc_packet *p);
static int job_set_description(struct initng_ipc_packet *p);
static int job_set_periodic(struct initng_ipc_packet *p);
static int job_set_argv(struct initng_ipc_packet *p);
static int job_set_env(struct initng_ipc_packet *p);
static int job_set_msn(struct initng_ipc_packet *p);
static int job_set_flags(struct initng_ipc_packet *p);
static int job_add_fd(struct initng_ipc_packet *p, struct initng_ipc_conn *thisconn);
static void send_ack_packet(struct initng_ipc_conn *thisconn, int r);
static int _fd(int fd);

int main(int argc, char *argv[])
{
	int ch, debug = 0;
	const char *thesockpath = getenv(INITNG_SOCKET_ENV);

	argv0 = argv[0];

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "dhs:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 's':
			thesockpath = optarg;
			break;
		case 'h':
			usage(stdout);
			break;
		case '?':
		default:
			usage(stderr);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (!debug)
		daemon(0, 0);

	openlog((const char*)basename(argv0), LOG_CONS|(debug ? LOG_PERROR : 0), LOG_DAEMON);

	if ((kq = _fd(kqueue())) == -1)
		initngd_panic("kqueue(): %m");
	initsocket(thesockpath);
	therunloop();
}

static void initsocket(const char *thepath)
{
	struct sockaddr_un sun;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, thepath ? thepath : INITNG_SOCKET_DEFAULT, sizeof(sun.sun_path));

	if ((thesocket = _fd(socket(AF_UNIX, SOCK_STREAM, 0))) == -1)
		initngd_panic("socket(): %m");
	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		initngd_debug(LOG_WARNING, "unlink(): %m");
	if (bind(thesocket, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		initngd_panic("bind(): %m");
	if (listen(thesocket, 255) == -1)
		initngd_panic("listen(): %m");
	kevent_add_one(thesocket, EVFILT_READ, EV_ADD, 0, 0, NULL);
}

static void therunloop(void)
{
	/* don't bump up until we can deal with cleaning up another event after closing a fd */
#define KEVS_AT_A_TIME 1
	struct kevent kev[KEVS_AT_A_TIME];
	int r, i;

	for (;;) {
		r = kevent(kq, NULL, 0, kev, KEVS_AT_A_TIME, NULL);
		if (r == -1) {
			initngd_debug(LOG_DEBUG, "kevent(): %m");
			continue;
		}
		for (i = 0; i < r; i++)
			handle_event(kev + i);
	}
	/* we shouldn't get here */
	initngd_panic("end of the runloop reached");
}

static void handle_event(struct kevent *kev)
{
	struct initng_job *j = (struct initng_job *)kev->udata;
	if (j && (kev->filter == EVFILT_PROC)) {
		reap_job(j);
	} else if (j) {
	    	if (j->flags & JOB_INETD_ST)
			launch_job_st(j);
		else
			launch_job(j);
	} else if ((int)kev->ident == thesocket) {
		do_accept_logic();
	} else {
		do_ipc_logic(kev);
	}
}

static void do_accept_logic(void)
{
	struct sockaddr_un sun;
	int r;
	socklen_t sl = sizeof(sun);

	r = _fd(accept(thesocket, (struct sockaddr *)&sun, &sl));
	if (r == -1) {
		initngd_debug(LOG_DEBUG, "accept(): %m");
		return;
	}
	if (fcntl(r, F_SETFL, O_NONBLOCK) == -1)
		initngd_debug(LOG_DEBUG, "fcntl(O_NONBLOCK): %m");

	create_ipc_conn(r);
}

static struct initng_ipc_conn *create_ipc_conn(int fd)
{
	struct initng_ipc_conn *c = calloc(1, sizeof(struct initng_ipc_conn));
	c->fd = fd;
	c->sendbuf = malloc(0);
	c->sendctrlbuf = malloc(0);
	c->recvbuf = malloc(0);
	c->recvctrlbuf = malloc(0);
	TAILQ_INSERT_TAIL(&theconnections, c, tqe);
	kevent_add_one(c->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	return c;
}

static void do_ipc_logic(struct kevent *kev)
{
	struct initng_ipc_conn *thisconn = find_conn_with_fd(kev->ident);
	struct msghdr mh;
	struct iovec iov;
	int r;

	if (!thisconn) {
		initngd_debug(LOG_DEBUG, "connection not found during IPC logic: kev->ident = %ld", kev->ident);
		return;
	}

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	if (kev->filter == EVFILT_WRITE) {
		iov.iov_base = thisconn->sendbuf;
		iov.iov_len = thisconn->sendlen;
		mh.msg_control = thisconn->sendctrllen ? thisconn->sendctrlbuf : NULL;
		mh.msg_controllen = thisconn->sendctrllen;

		r = sendmsg(thisconn->fd, &mh, 0);
		if (r <= 0) {
			if (r == -1 && errno != EPIPE)
				initngd_debug(LOG_DEBUG, "sendmsg(thisconn): %m");
			return close_ipc_conn(thisconn);
		}
		memmove(thisconn->sendbuf, thisconn->sendbuf + r, r);
		memmove(thisconn->sendctrlbuf, thisconn->sendctrlbuf + mh.msg_controllen, mh.msg_controllen);
		thisconn->sendlen -= r;
		thisconn->sendctrllen -= mh.msg_controllen;
		if (thisconn->sendlen == 0 && thisconn->sendctrllen == 0) {
			thisconn->sendbuf = realloc(thisconn->sendbuf, 0);
			thisconn->sendctrlbuf = realloc(thisconn->sendctrlbuf, 0);
			kevent_add_one(thisconn->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		}
	} else if (kev->filter == EVFILT_READ) {
		thisconn->recvbuf = realloc(thisconn->recvbuf, thisconn->recvlen + 16*1024);
		thisconn->recvctrlbuf = realloc(thisconn->recvctrlbuf, thisconn->recvlen + 4*1024);

		iov.iov_base = thisconn->recvbuf + thisconn->recvlen;
		iov.iov_len = 16*1024;
		mh.msg_control = thisconn->recvctrlbuf + thisconn->recvctrllen;
		mh.msg_controllen = 4*1024;

		r = recvmsg(thisconn->fd, &mh, 0);
		if (r <= 0) {
			if (r == -1 && errno != EPIPE)
				initngd_debug(LOG_DEBUG, "recvmsg(thisconn): %m");
			return close_ipc_conn(thisconn);
		}
		if (mh.msg_flags & MSG_CTRUNC) {
			initngd_debug(LOG_DEBUG, "recvmsg(thisconn): not enough control message buffer space");
			return close_ipc_conn(thisconn);
		}
		thisconn->recvlen += r;
		thisconn->recvctrllen += mh.msg_controllen;
		parse_packets(thisconn);
	} else {
		initngd_panic("unknown filter type: %d", kev->filter);
	}
}

static void initngd_panic(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsyslog(LOG_EMERG, format, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void initngd_debug(int priority, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsyslog(priority, format, ap);
	va_end(ap);
}

static int kevent_add_one(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	EV_SET(&kev, ident, filter, flags, fflags, data, udata);
	return kevent(kq, &kev, 1, NULL, 0, NULL);
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

static void close_ipc_conn(struct initng_ipc_conn *conn)
{
	TAILQ_REMOVE(&theconnections, conn, tqe);
	free(conn->sendbuf);
	free(conn->sendctrlbuf);
	free(conn->recvbuf);
	free(conn->recvctrlbuf);
	close(conn->fd);
	free(conn);
}

static void parse_packets(struct initng_ipc_conn *thisconn)
{
	struct initng_ipc_packet *p;
	size_t p_len;
	int r;

start_over:
	p = thisconn->recvbuf;
	if (thisconn->recvlen < sizeof(struct initng_ipc_packet))
		return;
	p_len = sizeof(struct initng_ipc_packet) + p->data_len;
	if (thisconn->recvlen < p_len)
		return;

	switch (p->command) {
	case INITNG_CREATE:
		r = job_create(p); break;
	case INITNG_REMOVE:
		r = job_remove(p); break;
	case INITNG_SET_FLAG_ENABLED:
	case INITNG_SET_FLAG_ON_DEMAND:
	case INITNG_SET_FLAG_BATCH:
	case INITNG_SET_FLAG_LAUNCH_ONCE:
	case INITNG_SET_FLAG_SUPPORTS_MGMT:
	case INITNG_SET_FLAG_INETD_SINGLE_THREADED:
		r = job_set_flags(p); break;
	case INITNG_SET_UID:
		r = job_set_uid(p); break;
	case INITNG_SET_GID:
		r = job_set_gid(p); break;
	case INITNG_SET_PROGRAM:
		r = job_set_program(p); break;
	case INITNG_SET_ARGV:
		r = job_set_argv(p); break;
	case INITNG_SET_ENV:
		r = job_set_env(p); break;
	case INITNG_SET_MACH_SERVICE_NAMES:
		r = job_set_msn(p); break;
	case INITNG_SET_PERIODIC:
		r = job_set_periodic(p); break;
	case INITNG_SET_DESCRIPTION:
		r = job_set_description(p); break;
	case INITNG_ADD_FD:
		r = job_add_fd(p, thisconn); break;
	default:
		initngd_debug(LOG_DEBUG, "Unknown packet found: %d on %p", p->command, thisconn);
		r = -1;
		break;
	}
	send_ack_packet(thisconn, r);
	memmove(thisconn->recvbuf, thisconn->recvbuf + p_len, thisconn->recvlen - p_len);
	thisconn->recvlen -= p_len;
	goto start_over;
}

static void usage(FILE *where)
{
	fprintf(where, "%s:\n", argv0);
	fprintf(where, "\t-d\tdebug mode\n");
	fprintf(where, "\t-s sock\talternate socket to use\n");
	fprintf(where, "\t-h\tthis usage statement\n");

	if (where == stdout)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}

static void launch_job_st(struct initng_job *j)
{
	struct sockaddr_storage sas;
	socklen_t sl = sizeof(sas);
	int fd;
	pid_t c;

	fd = accept(TAILQ_FIRST(&j->thefds)->fd, (struct sockaddr *)&sas, &sl);

	if ((c = fork()) == -1) {
		initngd_debug(LOG_DEBUG, "fork(): %m");
		close(fd);
		return;
	} else if (c) {
		close(fd);
		return;
	} else {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
		setgid(j->g);
		setuid(j->u);
		execve(j->program, j->argv, environ);
		_exit(EXIT_FAILURE);
	}
}

static void launch_job(struct initng_job *j)
{
	int pair[2];
	pid_t c;

	j->flags |= JOB_RUNNING;
	runloop_ignore(j);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		initngd_debug(LOG_DEBUG, "socketpair(): %m");
		goto out;
	}
	j->trusted_conn = create_ipc_conn(_fd(pair[0]));
	if ((c = fork()) == -1) {
		initngd_debug(LOG_DEBUG, "fork(): %m");
		goto out3;
	} else if (c) {
		close(pair[1]);
		j->p = c;
		if (kevent_add_one(j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, j) == -1) {
			if (errno != ESRCH)
				initngd_debug(LOG_DEBUG, "kevent(): %m");
			goto out2;
		}
	} else {
		char *envret;
		asprintf(&envret, "%d", pair[1]);
		setenv("INITNGD_FD", envret, 1);
		free(envret);

		setgid(j->g);
		setuid(j->u);
		/* XXX -- ammend the environ */
		execve(j->program, j->argv, environ);
		_exit(EXIT_FAILURE);
	}
	return;
out3:
	close (pair[1]);
out2:
	close_ipc_conn(j->trusted_conn);
out:
	if (j->p) {
		reap_job(j);
	} else {
		j->flags &= ~JOB_RUNNING;
		runloop_observe(j);
	}
}

static void reap_job(struct initng_job *j)
{
	int status;

	waitpid(j->p, &status, 0);
	if (WIFSIGNALED(status))
		initngd_debug(LOG_WARNING, "%s[%d] exited abnormally with signal %d", j->program, j->p, WTERMSIG(status));
	else if (WIFEXITED(status) && WEXITSTATUS(status) > 0)
		initngd_debug(LOG_WARNING, "%s[%d] exited with exit code %d", j->program, j->p, WEXITSTATUS(status));
	j->p = 0;
	j->flags &= ~JOB_RUNNING;
	runloop_observe(j);
}

static void runloop_ignore(struct initng_job *j)
{
	struct initng_job_fd *jfd;
	TAILQ_FOREACH(jfd, &j->thefds, tqe)
		kevent_add_one(jfd->fd, EVFILT_READ, EV_DELETE, 0, 0, j);
}

static void runloop_observe(struct initng_job *j)
{
	if ((j->flags & JOB_ENABLED) && !(j->flags & JOB_RUNNING)) {
		struct initng_job_fd *jfd;
		TAILQ_FOREACH(jfd, &j->thefds, tqe)
			kevent_add_one(jfd->fd, EVFILT_READ, EV_ADD, 0, 0, j);
	}
}

static struct initng_job *job_find(char *uuid)
{
	struct initng_job *j;

	TAILQ_FOREACH(j, &thejobs, tqe) {
		if (memcmp(j->uuid, uuid, 16) == 0)
			return j;
	}
	return NULL;
}

static int job_create(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (j) return -1;
	j = calloc(1, sizeof(struct initng_job));
	memcpy(j->uuid, p->uuid, 16);
	TAILQ_INIT(&j->thefds);
	TAILQ_INSERT_TAIL(&thejobs, j, tqe);
	return 0;
}

static int job_remove(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	TAILQ_REMOVE(&thejobs, j, tqe);
	return 0;
}

static int job_set_uid(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	j->u = *((uid_t *)p->data);
	return 0;
}

static int job_set_gid(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	j->g = *((gid_t *)p->data);
	return 0;
}

static int job_set_periodic(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	j->periodic = *((unsigned int *)p->data);
	return 0;
}

static int job_set_description(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	if (j->description)
		free(j->description);
	j->description = strdup(p->data);
	return 0;
}

static int job_set_program(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	if (j->program)
		free(j->program);
	j->program = strdup(p->data);
	return 0;
}

/* linear string to vector dup */
static char **lstring2vdup(void *data, size_t data_len)
{
	char *tmp = malloc(data_len);
	char *lastseenstring = NULL;
	char **r;
	size_t argc = 0;
	unsigned int i, j = 0;

	memcpy(tmp, data, data_len);

	for (i = 0; i < data_len; i++) {
		if (tmp[i] == NULL)
			argc++;
	}
	r = malloc((argc * sizeof(char*)) + 1);
	r[argc] = NULL;
	lastseenstring = tmp;
	for (i = 0; i < data_len; i++) {
		if (tmp[i] == NULL) {
			r[j] = lastseenstring;
			j++;
			lastseenstring = &(tmp[i]) + 1;
		}
	}
	return r;
}

static int job_set_argv(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	if (j->argv) {
		free(j->argv[0]);
		free(j->argv);
	}
	j->argv = lstring2vdup(p->data, p->data_len);
	return 0;
}

static int job_set_env(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	if (j->env) {
		free(j->env[0]);
		free(j->env);
	}
	j->env = lstring2vdup(p->data, p->data_len);
	return 0;
}

static int job_set_msn(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);

	if (!j) return -1;
	if (j->msn) {
		free(j->msn[0]);
		free(j->msn);
	}
	j->msn = lstring2vdup(p->data, p->data_len);
	return 0;
}

static int job_add_fd(struct initng_ipc_packet *p, struct initng_ipc_conn *thisconn)
{
	struct initng_job *j = job_find(p->uuid);
	struct initng_job_fd *jfd;
	struct cmsghdr *cm = thisconn->recvctrlbuf;
	int r = -1;

	if (!j) goto out_bad;

	if (thisconn->recvctrllen == 0) {
		initngd_debug(LOG_DEBUG, "attempted to add a FD without ancillary data");
		goto out_bad;
	}

	if (cm->cmsg_len != CMSG_LEN(sizeof(int)) || cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS) {
		initngd_debug(LOG_DEBUG, "bogus ancillary data recieved");
		goto out;
	}

	jfd = calloc(1, sizeof(struct initng_job_fd));
	jfd->fd = _fd(*((int*)CMSG_DATA(cm)));
	if (p->data) {
		jfd->data = malloc(p->data_len);
		memcpy(jfd->data, p->data, p->data_len);
		jfd->data_len = p->data_len;
	}
	TAILQ_INSERT_TAIL(&j->thefds, jfd, tqe);
	r = 0;
out:
	memmove(thisconn->recvctrlbuf, thisconn->recvctrlbuf + cm->cmsg_len, thisconn->recvctrllen - cm->cmsg_len);
	thisconn->recvctrllen -= cm->cmsg_len;
out_bad:
	return r;
}

static int job_set_flags(struct initng_ipc_packet *p)
{
	struct initng_job *j = job_find(p->uuid);
	bool b = *((bool*)p->data);

	if (!j) return -1;

	switch (p->command) {
	case INITNG_SET_FLAG_ENABLED:
		if (b) {
			bool doit = !(j->flags & JOB_ENABLED);
			j->flags |=  JOB_ENABLED;
			if (doit)
				runloop_observe(j);
		} else {
			if (j->flags & JOB_ENABLED)
				runloop_ignore(j);
			j->flags &= ~JOB_ENABLED;
		}
		break;
	case INITNG_SET_FLAG_ON_DEMAND:
		if (b) j->flags |=  JOB_ON_DEMAND;
		else   j->flags &= ~JOB_ON_DEMAND;
		break;
	case INITNG_SET_FLAG_BATCH:
		if (b) j->flags |=  JOB_BATCH;
		else   j->flags &= ~JOB_BATCH;
		break;
	case INITNG_SET_FLAG_LAUNCH_ONCE:
		if (b) j->flags |=  JOB_LAUNCH_ONCE;
		else   j->flags &= ~JOB_LAUNCH_ONCE;
		break;
	case INITNG_SET_FLAG_SUPPORTS_MGMT:
		if (b) j->flags |=  JOB_SUPPORTS_MGMT;
		else   j->flags &= ~JOB_SUPPORTS_MGMT;
		break;
	case INITNG_SET_FLAG_INETD_SINGLE_THREADED:
		if (b) j->flags |=  JOB_INETD_ST;
		else   j->flags &= ~JOB_INETD_ST;
		break;
	default:
		initngd_debug(LOG_DEBUG, "Unknown flag being set: %d", p->command);
		break;
	}
	return 0;
}

static void send_ack_packet(struct initng_ipc_conn *thisconn, int r)
{
	struct initng_ipc_packet p;
	size_t old_offset = thisconn->sendlen;

	memset(&p, 0, sizeof(p));
	p.version = INITNG_PROTOCOL_VERSION;
	p.command = INITNG_ACK;
	p.return_code = r;

	thisconn->sendbuf = realloc(thisconn->sendbuf, old_offset + sizeof(p));
	memcpy(thisconn->sendbuf + old_offset, &p, sizeof(p));
	thisconn->sendlen += sizeof(p);

	kevent_add_one(thisconn->fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
}

static int _fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}
