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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>

#define INITNG_PRIVATE_API
#include "libinitng.h"

extern char **environ;

struct initngd_jobfd {
	TAILQ_ENTRY(initngd_jobfd) tqe;
	int fd;
	char *label;
};


struct initngd_job {
	TAILQ_ENTRY(initngd_job) tqe;
	unsigned int enabled:1, on_demand:1, batch:1, launch_once:1,
		supports_mgmt:1, running:1, compat_inetd_wait:1,
		compat_inetd_nowait:1, is_initngd:1;
	int setup_conn;
	pid_t p;
	uid_t u;
	gid_t g;
	mode_t um;
	char *label;
	char *description;
	char *program;
	char **argv;
	char **env;
	char **msn;
	unsigned int periodic;
	void (*wn)(struct initngd_job *j, struct kevent *kev);
	struct timeval lastrun;
	TAILQ_HEAD(initngd_jobfds, initngd_jobfd) fds;
};

TAILQ_HEAD(initngd_jobs, initngd_job) thejobs = TAILQ_HEAD_INITIALIZER(thejobs);

static int thesocket = 0;
static int thewebsocket = 0;
static int kq = 0;
static char *argv0 = NULL;
static struct initngd_job *thejob = NULL;

static void initngd_parse_packet(int fd, char *command, char *data[], void *cookie, initng_cred_t *cred);
static void initngd_do_web_feedback(int lfd);
static void job_launch(struct initngd_job *j, struct kevent *kev);
static void job_reap(struct initngd_job *j, struct kevent *kev);
static void job_observe(struct initngd_job *j);
static void job_ignore(struct initngd_job *j);
static void job_remove(struct initngd_job *j);
static void job_dump_state(struct initngd_job *j, int fd);
static struct initngd_job *job_find(const char *label);
static struct initngd_jobfd *job_fd_find(struct initngd_job *j, const char *label);
static void initngd_internal_wn(struct initngd_job *j, struct kevent *kev);

/* utility functions */
static char **stringvdup(char **sv);
static void freestringv(char **sv);
static void usage(FILE *where) __attribute__((noreturn));
static void initngd_debug(int priority, const char *format, ...) __attribute__((format(printf,2,3)));
static void initngd_panic(const char *format, ...) __attribute__((noreturn, format(printf,1,2)));
static int __kevent(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);
static int _fd(int fd);

#define initngd_assert(expression) ((void)((expression) ? 0 : __initngd_assert(#expression, __FILE__, __LINE__)))
#define __initngd_assert(expression, file, line) (initngd_panic("%s:%u failed assertion: %s", file, line, expression), 0)

int main(int argc, char *argv[])
{
	const char *thesockpath = NULL;
	struct kevent kev, k;
	struct initngd_job *j, *ji;
	int tmpfd, r, ch, debug = 0;

	EV_SET(&k, 0, EVFILT_PROC, 0, 0, 0, 0);

	argv0 = argv[0];

	thejob = calloc(1, sizeof(struct initngd_job));
	thejob->label = "__initngd__";
	thejob->enabled = 1;
	thejob->supports_mgmt = 1;
	thejob->running = 1;
	thejob->is_initngd = 1;
	thejob->u = getuid();
	thejob->g = getgid();
	thejob->p = getpid();
	thejob->argv = argv;
	thejob->env = environ;
	thejob->wn = initngd_internal_wn;
	TAILQ_INIT(&thejob->fds);
	TAILQ_INSERT_TAIL(&thejobs, thejob, tqe);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

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

	openlog((const char*)basename(argv0), LOG_CONS|(debug ? LOG_PERROR : 0), LOG_DAEMON);

	if (!debug) {
		if (getpid() > 1) {
			switch (fork()) {
			case -1:
				initngd_panic("fork(): %m");
			default:
				exit(EXIT_SUCCESS);
			case 0:
				break;
			}
		}
		tmpfd = open("/dev/null", O_RDWR);
		dup2(tmpfd, STDIN_FILENO);
		dup2(tmpfd, STDOUT_FILENO);
		dup2(tmpfd, STDERR_FILENO);
		close(tmpfd);
	} else {
		struct sockaddr_in sain;
		int sock_opt = 1;

		memset(&sain, 0, sizeof(sain));
		sain.sin_family = AF_INET;
		sain.sin_port = htons(12345);
		sain.sin_addr.s_addr = htonl(0x7f000001);

		if ((thewebsocket = _fd(socket(AF_INET, SOCK_STREAM, 0))) == -1)
			initngd_panic("socket(): %m");
		if (setsockopt(thewebsocket, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt, sizeof(sock_opt)) == -1)
			initngd_panic("setsockopt(): %m");
		if (bind(thewebsocket, (struct sockaddr *)&sain, sizeof(sain)) == -1)
			initngd_panic("bind(): %m");
		if (listen(thewebsocket, 255) == -1)
			initngd_panic("listen(): %m");
	}

	chdir("/");
	setsid();

	if ((kq = _fd(kqueue())) == -1)
		initngd_panic("kqueue(): %m");

	if (thewebsocket)
		__kevent(thewebsocket, EVFILT_READ, EV_ADD, 0, 0, thejob);

	if ((thesocket = _fd(initng_server_init(thesockpath))) == -1)
		initngd_panic("initng_server_init(): %m");
	__kevent(thesocket, EVFILT_READ, EV_ADD, 0, 0, thejob);

	for (;;) {
		if ((r = kevent(kq, NULL, 0, &kev, 1, NULL)) == -1) {
			initngd_debug(LOG_DEBUG, "kevent(): %m");
			continue;
		}

		j = (struct initngd_job *)kev.udata;

		j->wn(j, &kev);

		TAILQ_FOREACH(ji, &thejobs, tqe) {
			if (ji->enabled && !ji->on_demand && !ji->running)
				job_launch(ji, &k);
		}
	}
}

static void initngd_internal_wn(struct initngd_job *j, struct kevent *kev)
{
	struct initngd_job *ji;
	int fd;

	if ((int)kev->ident == thesocket) {
		if ((fd = initng_server_accept(thesocket)) == -1) {
			initngd_debug(LOG_DEBUG, "initng_server_accept(): %m");
			return;
		}
		__kevent(_fd(fd), EVFILT_READ, EV_ADD, 0, 0, thejob);
	} else if ((int)kev->ident == thewebsocket) {
		initngd_do_web_feedback(thewebsocket);
	} else if (kev->filter == EVFILT_READ) {
		if (initng_recvmsg(kev->ident, initngd_parse_packet, j) == -1) {
			if (errno == EAGAIN)
			       return;
			if (errno != ECONNRESET)
				initngd_debug(LOG_DEBUG, "initng_recvmsg(): %m");
			TAILQ_FOREACH(ji, &thejobs, tqe) {
				if ((int)kev->ident == ji->setup_conn)
					job_remove(ji);
			}
			initng_close(kev->ident);
		}
	} else if (kev->filter == EVFILT_WRITE) {
		if (initng_flush(kev->ident) == -1) {
			if (errno == EAGAIN)
				return;
			initngd_debug(LOG_DEBUG, "initng_flush(): %m");
			TAILQ_FOREACH(ji, &thejobs, tqe) {
				if ((int)kev->ident == ji->setup_conn)
					job_remove(ji);
			}
			initng_close(kev->ident);
		}
		__kevent(kev->ident, EVFILT_WRITE, EV_DELETE, 0, 0, thejob);
	}
}

static void launch_job_st(struct initngd_job *j)
{
	struct sockaddr_storage sas;
	socklen_t sl = sizeof(sas);
	char **tmp, *tmps;
	int fd;
	pid_t c;

	fd = accept((TAILQ_FIRST(&j->fds))->fd, (struct sockaddr *)&sas, &sl);

	if ((c = fork()) == -1) {
		initngd_debug(LOG_DEBUG, "fork(): %m");
		close(fd);
		return;
	} else if (c) {
		close(fd);
		return;
	} else {
		for (tmp = j->env; *tmp; tmp++) {
			tmps = strchr(*tmp, '=');
			if (tmps) {
				*tmps = '\0';
				tmps++;
				setenv(*tmp, tmps, 1);
			}
		}
		if (dup2(fd, STDIN_FILENO) == -1)
			initngd_debug(LOG_DEBUG, "child dup2(fd, 0): %m");
		if (dup2(fd, STDOUT_FILENO) == -1)
			initngd_debug(LOG_DEBUG, "child dup2(fd, 1): %m");
		if (dup2(fd, STDERR_FILENO) == -1)
			initngd_debug(LOG_DEBUG, "child dup2(fd, 2): %m");
		close(fd);
		setgid(j->g);
		setuid(j->u);
		setsid();
		if (execve(j->program, j->argv, environ) == -1)
			initngd_debug(LOG_DEBUG, "child execve(): %m");
		_exit(EXIT_FAILURE);
	}
}

static void job_launch(struct initngd_job *j, struct kevent *kev)
{
	struct initngd_jobfd *jfd;
	pid_t c;
	char *rdata[] = { j->label, NULL, NULL };
	char **tmp, *tmps;
	char fds[4096];
	char fdlabelkey[1024];
	size_t fdindex = 0;

	initngd_assert(kev->filter == EVFILT_READ);

	if (j->compat_inetd_nowait)
		return launch_job_st(j);

	if ((c = fork()) == -1) {
		initngd_debug(LOG_DEBUG, "fork(): %m");
		return;
	} else if (c == 0) {
		if (j->env) {
			for (tmp = j->env; *tmp; tmp++) {
				tmps = strchr(*tmp, '=');
				if (tmps) {
					*tmps = '\0';
					tmps++;
					setenv(*tmp, tmps, 1);
				}
			}
		}
		TAILQ_FOREACH(jfd, &j->fds, tqe)
			fdindex += sprintf(fds + fdindex, "%d%s", jfd->fd, TAILQ_NEXT(jfd, tqe) ? " " : "");
		setenv("__INITNG_FDS", fds, 1);
		TAILQ_FOREACH(jfd, &j->fds, tqe) {
			fcntl(jfd->fd, F_SETFD, 0);
			sprintf(fdlabelkey, "__INITNG_FD_%d", jfd->fd);
			setenv(fdlabelkey, jfd->label, 1);
		}
		setgid(j->g);
		setuid(j->u);
		setsid();
		umask(j->um);
		if (execve(j->program, j->argv, environ) == -1)
			initngd_debug(LOG_DEBUG, "child execve(): %m");
		_exit(EXIT_FAILURE);
	}
	gettimeofday(&j->lastrun, NULL);
	if (__kevent(c, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, j) == -1) {
		initngd_debug(LOG_DEBUG, "kevent(): %m");
		return;
	}
	j->p = c;
	j->wn = job_reap;
	j->running = 1;
	asprintf(&(rdata[1]), "%d", j->p);
	initng_sendmsga2sniffers("notifyRunning", rdata);
	free(rdata[1]);
	job_ignore(j);
}

static void job_reap(struct initngd_job *j, struct kevent *kev)
{
	int status = 0;
	char *rdata[] = { j->label, "0", NULL };

	initngd_assert(kev->filter == EVFILT_PROC);

	waitpid(j->p, &status, 0);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) > 0)
			initngd_debug(LOG_WARNING, "%s[%d] exited with exit code %d", j->program, j->p, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		initngd_debug(LOG_WARNING, "%s[%d] exited abnormally with signal %d", j->program, j->p, WTERMSIG(status));
	}
	j->p = 0;
	j->running = 0;
	j->wn = job_launch;
	initng_sendmsga2sniffers("notifyRunning", rdata);
	job_observe(j);
}

static void job_ignore(struct initngd_job *j)
{
	struct initngd_jobfd *jfd;

	TAILQ_FOREACH(jfd, &j->fds, tqe) {
		if (__kevent(jfd->fd, EVFILT_READ, EV_DELETE, 0, 0, j) == -1)
			initngd_debug(LOG_DEBUG, "__kevent(%d, EV_DELETE): %m", jfd->fd);
	}
}

static void job_observe(struct initngd_job *j)
{
	struct initngd_jobfd *jfd;
	
	if (j->running || !j->on_demand)
		return;

	TAILQ_FOREACH(jfd, &j->fds, tqe) {
		if (__kevent(jfd->fd, EVFILT_READ, EV_ADD, 0, 0, j) == -1)
			initngd_debug(LOG_DEBUG, "__kevent(%d, EV_ADD): %m", jfd->fd);
	}
}

static struct initngd_job *job_find(const char *label)
{
	struct initngd_job *j;

	TAILQ_FOREACH(j, &thejobs, tqe) {
		if (!strcmp(j->label, label))
			return j;
	}
	return NULL;
}

static void job_remove(struct initngd_job *j)
{
	struct initngd_jobfd *jfd;

	if (j->p)
		__kevent(j->p, EVFILT_PROC, EV_DELETE, NOTE_EXIT, 0, j);
	TAILQ_FOREACH(jfd, &j->fds, tqe) {
		TAILQ_REMOVE(&j->fds, jfd, tqe);
		close(jfd->fd);
		free(jfd->label);
		free(jfd);
	}
	if (j->label)
		free(j->label);
	if (j->description)
		free(j->description);
	if (j->program)
		free(j->program);
	if (j->argv)
		freestringv(j->argv);
	if (j->env)
		freestringv(j->env);
	if (j->msn)
		freestringv(j->env);
	TAILQ_REMOVE(&thejobs, j, tqe);
	free(j);
}

static void initngd_parse_packet(int fd, char *command, char *data[], void *cookie, initng_cred_t *cred)
{
	struct initngd_job *j = NULL;
	char rstr[20], estr[20];
	int r = 0, e = 0;
	bool check_args(const char *expected, int count) {
		char **datatmp;
		int argc = 0;

		if (strcmp(expected, command))
			return false;
		for (datatmp = data; *datatmp; datatmp++)
			argc++;
		if (count < 0) {
		       	if (abs(count) > argc)
				return false;
		} else {
			if (argc != count)
				return false;
		}
		return true;
	};

	if (*data)
		j = job_find(*data);

	if (j && j->is_initngd) {
		r = -1;
		e = EPERM;
		goto out;
	}

	if (check_args("enableMonitor", 1)) {
		if (!strcmp(data[0], "true"))
			initng_set_sniffer(fd, true);
		else
			initng_set_sniffer(fd, false);
	} else if (check_args("createJob", 1)) {
		if (j) {
			r = -1;
			e = EEXIST;
			goto out;
		}

		j = calloc(1, sizeof(struct initngd_job));
		j->label = strdup(data[0]);
		TAILQ_INIT(&j->fds);
		j->setup_conn = fd;
		j->um = 077;
		j->wn = job_launch;
		j->on_demand = 1;
		TAILQ_INSERT_TAIL(&thejobs, j, tqe);
		goto out;
	} else if (!j) {
			r = -1;
			e = ENOENT;
	} else if (check_args("removeJob", 2)) {
		job_remove(j);
	} else if (check_args("enableJob", 2)) {
		j->setup_conn = 0;
		if (!strcmp(data[1], "true")) {
			j->enabled = 1;
			job_observe(j);
		} else {
			j->enabled = 0;
			job_ignore(j);
		}
	} else if (check_args("setInetdSingleThreaded", 2)) {
		if (!strcmp(data[1], "true"))
			j->compat_inetd_nowait = 1;
		else
			j->compat_inetd_nowait = 0;
	} else if (check_args("setInetdMultiThreaded", 2)) {
		/* can't set this flag if multiple FDs are a part of the job */
		if (TAILQ_FIRST(&j->fds) && TAILQ_NEXT(TAILQ_FIRST(&j->fds), tqe)) {
			r = -1;
			e = EINVAL;
			goto out;
		}
		if (!strcmp(data[1], "true"))
			j->compat_inetd_wait = 1;
		else
			j->compat_inetd_wait = 0;
	} else if (check_args("setUID", 2)) {
		j->u = (uid_t)strtol(data[1], NULL, 10);
	} else if (check_args("setGID", 2)) {
		j->g = (gid_t)strtol(data[1], NULL, 10);
	} else if (check_args("setProgram", 2)) {
		j->program = strdup(data[1]);
	} else if (check_args("setUmask", 2)) {
		mode_t tum = strtol(data[1], NULL, 8);
		if (tum == 0 && errno == EINVAL) {
			r = -1;
			e = EINVAL;
			goto out;
		}
		j->um = tum;
	} else if (check_args("setServiceDescription", 2)) {
		j->description = strdup(data[1]);
	} else if (check_args("setProgramArguments", -1)) {
		j->argv = stringvdup(data + 1);
	} else if (check_args("setMachServiceNames", -1)) {
		j->msn = stringvdup(data + 1);
	} else if (check_args("addFD", 3)) {
		int sfd = strtol(data[2], NULL, 10);
        	struct initngd_jobfd *jfd;

		/* can't add more than one FD if we're in inetd "wait" compatibility mode */
		if (j->compat_inetd_wait && TAILQ_FIRST(&j->fds)) {
			close(sfd);
			r = -1;
			e = EEXIST;
			goto out;
		}

		jfd = calloc(1, sizeof(struct initngd_jobfd));
		jfd->label = strdup(data[1]);
		jfd->fd = _fd(sfd);
		TAILQ_INSERT_TAIL(&j->fds, jfd, tqe);
	} else if (check_args("removeFD", 2)) {
        	struct initngd_jobfd *jfd;

		while ((jfd = job_fd_find(j, data[1]))) {
			TAILQ_REMOVE(&j->fds, jfd, tqe);
			close(jfd->fd);
			free(jfd->label);
			free(jfd);
		}
	} else if (check_args("setEnvironmentVariables", -1)) {
		j->env = stringvdup(data + 1);
	} else {
		initngd_debug(LOG_DEBUG, "fd %d and cookie %p: unknown command %s", fd, cookie, command);
		r = -1;
		e = EINVAL;
	}
out:
	snprintf(rstr, sizeof(rstr), "%d", r);
	snprintf(estr, sizeof(estr), "%d", e);
	if (initng_sendmsg(fd, "commandACK", rstr, estr, NULL) == -1)
		initngd_debug(LOG_DEBUG, "fd %d: failed to send ack for %s: %m", fd, command);
	if (r != -1)
		initng_sendmsga2sniffers(command, data);
}

static void initngd_do_web_feedback(int lfd)
{
	struct sockaddr_in sain;
	struct initngd_job *j;
	socklen_t slen = sizeof(sain);
	int afd;
	FILE *F;
	char **tmpv;

	if ((afd = accept(lfd, (struct sockaddr *)&sain, &slen)) == -1)
		return;

	F = fdopen(afd, "w+");

	fprintf(F, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n");

	fprintf(F, "<html><body><table border=\"1\" width=\"100%%\">");

	fprintf(F, "<tr>");
	fprintf(F, "<td>Label</td>");
	fprintf(F, "<td>Description</td>");
	fprintf(F, "<td>Program</td>");
	fprintf(F, "<td>PID</td>");
	fprintf(F, "<td>UID</td>");
	fprintf(F, "<td>GID</td>");
	fprintf(F, "<td>umask</td>");
	fprintf(F, "<td>Flags</td>");
	fprintf(F, "<td>argv</td>");
	fprintf(F, "<td>env</td>");
	fprintf(F, "<td>msn</td>");
	fprintf(F, "</tr>");

	TAILQ_FOREACH(j, &thejobs, tqe) {
		fprintf(F, "<tr>");
		fprintf(F, "<td>%s</td>", j->label);
		fprintf(F, "<td>%s</td>", j->description ? j->description : "");
		fprintf(F, "<td>%s</td>", j->program ? j->program : "");
		fprintf(F, "<td>%d</td>", j->p);
		fprintf(F, "<td>%d</td>", j->u);
		fprintf(F, "<td>%d</td>", j->g);
		fprintf(F, "<td>0%o</td>", j->um);
		fprintf(F, "<td>");
		fprintf(F, "%s ", j->enabled ? "enabled" : "");
		fprintf(F, "%s ", j->on_demand ? "on_demand" : "");
		fprintf(F, "%s ", j->batch ? "batch" : "");
		fprintf(F, "%s ", j->launch_once ? "launch_once" : "");
		fprintf(F, "%s ", j->supports_mgmt ? "supports_mgmt" : "");
		fprintf(F, "%s ", j->running ? "running" : "");
		fprintf(F, "%s ", j->compat_inetd_wait ? "compat_inetd_wait" : "");
		fprintf(F, "%s", j->compat_inetd_nowait ? "compat_inetd_nowait" : "");
		fprintf(F, "%s", j->is_initngd ? "is_initngd" : "");
		fprintf(F, "</td>");
		fprintf(F, "<td>");
		if (j->argv)
			for (tmpv = j->argv; *tmpv; tmpv++)
				fprintf(F, "%s<br>", *tmpv);
		fprintf(F, "</td>");
		fprintf(F, "<td>");
		if (j->env)
			for (tmpv = j->env; *tmpv; tmpv++)
				fprintf(F, "%s<br>", *tmpv);
		fprintf(F, "</td>");
		fprintf(F, "<td>");
		if (j->msn)
			for (tmpv = j->msn; *tmpv; tmpv++)
				fprintf(F, "%s<br>", *tmpv);
		fprintf(F, "</td></tr>");
	}

	fprintf(F, "</table></body></html>");

	fclose(F);
}

static struct initngd_jobfd *job_fd_find(struct initngd_job *j, const char *label)
{
	struct initngd_jobfd *jfd;

	 TAILQ_FOREACH(jfd, &j->fds, tqe) {
		 if (!strcmp(jfd->label, label))
			 return jfd;
	 }
	 return NULL;
}

/* the remaining are utility functions */

static char **stringvdup(char **sv)
{               
	char **r, **t;
	int s = 0;
	for (t = sv; *t; t++)
		s++;
	r = malloc((s + 1) * sizeof(char*));
	r[s] = NULL;
	t = sv;
	for (s = 0; *t; t++, s++)
		r[s] = strdup(*t);
	return r;
}       
        
static void freestringv(char **sv)
{                       
	char **tmp;
	for (tmp = sv;*tmp; tmp++)
		free(*tmp);
	free(sv);
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

static int __kevent(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	EV_SET(&kev, ident, filter, flags, fflags, data, udata);
	return kevent(kq, &kev, 1, NULL, 0, NULL);
}

static int _fd(int fd)
{
	if (fd >= 0) {
		fcntl(fd, F_SETFD, 1);
		fcntl(fd, F_SETFL, O_NONBLOCK);
	}
	return fd;
}
