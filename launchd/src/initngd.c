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

struct initng_job_fd {
	TAILQ_ENTRY(initng_job_fd) tqe;
	int fd;
	char *label;
};

struct initng_job {
	TAILQ_ENTRY(initng_job) tqe;
	unsigned int enabled:1, on_demand:1, batch:1, launch_once:1,
		supports_mgmt:1, running:1, compat_inetd_wait:1,
		compat_inetd_nowait:1;
	pid_t p;
	uid_t u;
	gid_t g;
	char *label;
	char *description;
	char *program;
	char **argv;
	char **env;
	char **msn;
	unsigned int periodic;
	TAILQ_HEAD(initng_job_fds, initng_job_fd) thefds;
};

TAILQ_HEAD(initng_jobs, initng_job) thejobs = TAILQ_HEAD_INITIALIZER(thejobs);

static int thesocket = 0;
static int thewebsocket = 0;
static int kq = 0;
static char *argv0 = NULL;

static void parse_packet(int fd, char *command, char *data[], void *cookie);
static void launch_job(struct initng_job *j);
static void launch_job_st(struct initng_job *j, int tfd);
static void reap_job(struct initng_job *j);
static void runloop_observe(struct initng_job *j);
static void runloop_ignore(struct initng_job *j);
static void do_web_feedback(void);
static void dump_job_state(int fd, struct initng_job *j);

/* utility functions */
static char **stringvdup(char **sv);
static void freestringv(char **sv);
static void usage(FILE *where) __attribute__((noreturn));
static void initngd_debug(int priority, const char *format, ...) __attribute__((format(printf,2,3)));
static void initngd_panic(const char *format, ...) __attribute__((noreturn, format(printf,1,2)));
static int __kevent(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);
static int _fd(int fd);

int main(int argc, char *argv[])
{
	const char *thesockpath = NULL;
	struct kevent kev;
	struct initng_job *j;
	initng_err_t ingerr;
	int r, fd, ch, debug = 0;

	argv0 = argv[0];

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

	if ((kq = _fd(kqueue())) == -1)
		initngd_panic("kqueue(): %m");

	if (!debug) {
		int tmpfd = open("/dev/null", O_RDWR);
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

		if ((thewebsocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			initngd_panic("socket(): %m");
		if (setsockopt(thewebsocket, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt, sizeof(sock_opt)) == -1)
			initngd_panic("setsockopt(): %m");
		if (bind(thewebsocket, (struct sockaddr *)&sain, sizeof(sain)) == -1)
			initngd_panic("bind(): %m");
		if (listen(thewebsocket, 255) == -1)
			initngd_panic("listen(): %m");
		__kevent(_fd(thewebsocket), EVFILT_READ, EV_ADD, 0, 0, NULL);
	}

	chdir("/");
	setsid();

	openlog((const char*)basename(argv0), LOG_CONS|(debug ? LOG_PERROR : 0), LOG_DAEMON);

	if ((ingerr = initng_server_init(&thesocket, thesockpath)) != INITNG_ERR_SUCCESS)
		initngd_panic("initng_server_init(): %s", initng_strerror(ingerr));
	__kevent(_fd(thesocket), EVFILT_READ, EV_ADD, 0, 0, NULL);

	for (;;) {
		if ((r = kevent(kq, NULL, 0, &kev, 1, NULL)) == -1) {
			initngd_debug(LOG_DEBUG, "kevent(): %m");
			continue;
		}

		j = (struct initng_job *)kev.udata;

		if (j && (kev.filter == EVFILT_PROC)) {
			reap_job(j);
		} else if (j) {
			if (j->compat_inetd_nowait)
				launch_job_st(j, kev.ident);
			else
				launch_job(j);
		} else if ((int)kev.ident == thesocket) {
			if ((ingerr = initng_server_accept(&fd, thesocket)) != INITNG_ERR_SUCCESS) {
				initngd_debug(LOG_DEBUG, "initng_server_accept(): %s", initng_strerror(ingerr));
				continue;
			}
			__kevent(_fd(fd), EVFILT_READ, EV_ADD, 0, 0, NULL);
		} else if ((int)kev.ident == thewebsocket) {
			do_web_feedback();
		} else if (kev.filter == EVFILT_READ) {
			ingerr = initng_recvmsg(kev.ident, parse_packet, j);
			if (ingerr != INITNG_ERR_SUCCESS && ingerr != INITNG_ERR_AGAIN) {
				if (ingerr != INITNG_ERR_BROKEN_CONN)
					initngd_debug(LOG_DEBUG, "initng_recvmsg(): %s", initng_strerror(ingerr));
				initng_close(kev.ident);
			}
		} else if (kev.filter == EVFILT_WRITE) {
			ingerr = initng_flush(kev.ident);
			if (ingerr == INITNG_ERR_SUCCESS) {
				__kevent(kev.ident, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
			} else if (ingerr == INITNG_ERR_AGAIN) {
				continue;
			} else {
				initngd_debug(LOG_DEBUG, "initng_flush(): %s", initng_strerror(ingerr));
				initng_close(kev.ident);
			}
		}
	}
}

static void launch_job_st(struct initng_job *j, int tfd)
{
	struct sockaddr_storage sas;
	socklen_t sl = sizeof(sas);
	int fd;
	pid_t c;

	fd = accept(tfd, (struct sockaddr *)&sas, &sl);

	if ((c = fork()) == -1) {
		initngd_debug(LOG_DEBUG, "fork(): %m");
		close(fd);
		return;
	} else if (c) {
		close(fd);
		return;
	} else {
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

static void launch_job(struct initng_job *j)
{
	pid_t c;
	char *rdata[] = { j->label, NULL, NULL };

	runloop_ignore(j);

	if ((c = fork()) == -1) {
		initngd_debug(LOG_DEBUG, "fork(): %m");
		goto out_bad;
	} else if (c) {
		j->p = c;
		if (__kevent(j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, j) == -1) {
			if (errno != ESRCH)
				initngd_debug(LOG_DEBUG, "kevent(): %m");
			goto out_bad;
		}
	} else {
		setenv("INITNG_JOB_LABEL", j->label, 1);
		setgid(j->g);
		setuid(j->u);
		setsid();
		if (execve(j->program, j->argv, environ) == -1)
			initngd_debug(LOG_DEBUG, "child execve(): %m");
		_exit(EXIT_FAILURE);
	}
	j->running = 1;
	asprintf(&(rdata[1]), "%d", j->p);
	initng_sendmsga2sniffers("notifyRunning", rdata);
	free(rdata[1]);
	return;
out_bad:
	if (j->p) {
		reap_job(j);
	} else {
		runloop_observe(j);
	}
}

static void reap_job(struct initng_job *j)
{
	int status = 0;
	char *rdata[] = { j->label, "0", NULL };

	waitpid(j->p, &status, 0);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) > 0)
			initngd_debug(LOG_WARNING, "%s[%d] exited with exit code %d", j->program, j->p, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status))
		initngd_debug(LOG_WARNING, "%s[%d] exited abnormally with signal %d", j->program, j->p, WTERMSIG(status));
	j->p = 0;
	j->running = 0;
	initng_sendmsga2sniffers("notifyRunning", rdata);
	runloop_observe(j);
}

static void runloop_ignore(struct initng_job *j)
{
	struct initng_job_fd *jfd;
	TAILQ_FOREACH(jfd, &j->thefds, tqe)
		__kevent(jfd->fd, EVFILT_READ, EV_DELETE, 0, 0, j);
}

static void runloop_observe(struct initng_job *j)
{
	if (j->enabled && !j->running) {
		struct initng_job_fd *jfd;
		TAILQ_FOREACH(jfd, &j->thefds, tqe)
			__kevent(jfd->fd, EVFILT_READ, EV_ADD, 0, 0, j);
	}
}

static struct initng_job *job_find(char *label)
{
	struct initng_job *j;

	TAILQ_FOREACH(j, &thejobs, tqe) {
		if (!strcmp(j->label, label))
			return j;
	}
	return NULL;
}

static void job_remove_cleanup(struct initng_job *j)
{
	struct initng_job_fd *jfd;

	if (j->p)
		__kevent(j->p, EVFILT_PROC, EV_DELETE, NOTE_EXIT, 0, j);
	TAILQ_FOREACH(jfd, &j->thefds, tqe) {
		TAILQ_REMOVE(&j->thefds, jfd, tqe);
		close(jfd->fd);
		free(jfd->label);
		free(jfd);
	}
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

static void parse_packet(int fd, char *command, char *data[], void *cookie)
{
	struct initng_job *j = NULL;
	char **datatmp;
	char *r = "success";
	int i, argc = 0, dodump = 0;
	initng_err_t ingerr;
	static struct arg_check_s {
		const char *command;
		int arg_count;
	} arg_check[] = {
		{ "dumpJobState", 1 }, /* label */
		{ "enableMonitor", 1 }, /* true/false */
		{ "createJob", 1 }, /* label */
		{ "removeJob", 1 }, /* label */
		{ "enableJob", 2 }, /* label, true/false */
		{ "setInetdSingleThreaded", 2 }, /* label, true/false */
		{ "setUID", 2 }, /* label, uid */
		{ "setGID", 2 }, /* label, gid */
		{ "setProgram", 2 }, /* label, path */
		{ "setServiceDescription", 2 }, /* label, desc */
		{ "addFD", 3 }, /* label, fd label, fd count */
	};

	for (datatmp = data; *datatmp; datatmp++)
		argc++;
	for (i = 0; i < (int)(sizeof(arg_check) / sizeof(struct arg_check_s)); i++) {
		if (!strcmp(command, arg_check[i].command) &&
				argc != arg_check[i].arg_count) {
			r = "malformed message";
			goto out;
		}
	}

	if (*data)
		j = job_find(*data);

	if (!strcmp(command, "enableMonitor")) {
		if (!strcmp(data[0], "true"))
			initng_set_sniffer(fd, true);
		else
			initng_set_sniffer(fd, false);
	} else if (!strcmp(command, "createJob")) {
		if (j) {
			r = "job exists";
			goto out;
		}

		j = calloc(1, sizeof(struct initng_job));
		j->label = strdup(*data);
		TAILQ_INIT(&j->thefds);
		TAILQ_INSERT_TAIL(&thejobs, j, tqe);
		goto out;
	} else if (!j) {
			r = "job not found";
	} else if (!strcmp(command, "dumpJobState")) {
		dodump = 1;
	} else if (!strcmp(command, "removeJob")) {
		job_remove_cleanup(j);
	} else if (!strcmp(command, "enableJob")) {
		if (!strcmp(data[1], "true"))
			j->enabled = 1;
		else
			j->enabled = 0;
		runloop_observe(j);
	} else if (!strcmp(command, "setInetdSingleThreaded")) {
		if (!strcmp(data[1], "true"))
			j->compat_inetd_nowait = 1;
		else
			j->compat_inetd_nowait = 0;
	} else if (!strcmp(command, "setUID")) {
		j->u = (uid_t)strtol(data[1], NULL, 10);
	} else if (!strcmp(command, "setGID")) {
		j->g = (gid_t)strtol(data[1], NULL, 10);
	} else if (!strcmp(command, "setProgram")) {
		j->program = strdup(data[1]);
	} else if (!strcmp(command, "setServiceDescription")) {
		j->description = strdup(data[1]);
	} else if (!strcmp(command, "setEnvironmentVariables")) {
		j->env = stringvdup(data + 1);
	} else if (!strcmp(command, "setProgramArguments")) {
		j->argv = stringvdup(data + 1);
	} else if (!strcmp(command, "setMachServiceNames")) {
		j->msn = stringvdup(data + 1);
	} else if (!strcmp(command, "addFD")) {
		int sfd = strtol(data[2], NULL, 10);
        	struct initng_job_fd *jfd;

		jfd = calloc(1, sizeof(struct initng_job_fd));
		jfd->label = strdup(data[1]);
		jfd->fd = _fd(sfd);
       		TAILQ_INSERT_TAIL(&j->thefds, jfd, tqe);
	} else {
		initngd_debug(LOG_DEBUG, "fd %d and cookie %p: unknown command %s", fd, cookie, command);
		r = "unknown command";
	}
out:
	if (!dodump) {
		ingerr = initng_sendmsg(fd, "commandACK", r, NULL);
		if (ingerr != INITNG_ERR_SUCCESS)
			initngd_debug(LOG_DEBUG, "fd %d: failed to send command acknowledgement: %s", fd, initng_strerror(ingerr));
	}
	initng_sendmsga2sniffers(command, data);
	if (dodump)
		dump_job_state(fd, j);
}

static void do_web_feedback(void)
{
	struct sockaddr_in sain;
	struct initng_job *j;
	socklen_t slen = sizeof(sain);
	int afd;
	FILE *F;
	char **tmpv;

	if ((afd = accept(thewebsocket, (struct sockaddr *)&sain, &slen)) == -1)
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
	fprintf(F, "<td>Flags</td>");
	fprintf(F, "<td>argv</td>");
	fprintf(F, "<td>env</td>");
	fprintf(F, "<td>msn</td>");
	fprintf(F, "</tr>");

	TAILQ_FOREACH(j, &thejobs, tqe) {
		fprintf(F, "<tr>");
		fprintf(F, "<td>%s</td>", j->label);
		fprintf(F, "<td>%s</td>", j->description);
		fprintf(F, "<td>%s</td>", j->program);
		fprintf(F, "<td>%d</td>", j->p);
		fprintf(F, "<td>%d</td>", j->u);
		fprintf(F, "<td>%d</td>", j->g);
		fprintf(F, "<td>");
		fprintf(F, "%s ", j->enabled ? "enabled" : "");
		fprintf(F, "%s ", j->on_demand ? "on_demand" : "");
		fprintf(F, "%s ", j->batch ? "batch" : "");
		fprintf(F, "%s ", j->launch_once ? "launch_once" : "");
		fprintf(F, "%s ", j->supports_mgmt ? "supports_mgmt" : "");
		fprintf(F, "%s ", j->running ? "running" : "");
		fprintf(F, "%s ", j->compat_inetd_wait ? "compat_inetd_wait" : "");
		fprintf(F, "%s", j->compat_inetd_nowait ? "compat_inetd_nowait" : "");
		fprintf(F, "</td>");
		fprintf(F, "<td>");
		for (tmpv = j->argv; *tmpv; tmpv++)
			fprintf(F, "%s%s", *tmpv, *(tmpv + 1) ? " " : "");
		fprintf(F, "</td>");
		fprintf(F, "<td>");
		if (j->env)
			for (tmpv = j->env; *tmpv; tmpv++)
				fprintf(F, "%s%s", *tmpv, *(tmpv + 1) ? " " : "");
		fprintf(F, "</td>");
		fprintf(F, "<td>");
		if (j->msn)
			for (tmpv = j->msn; *tmpv; tmpv++)
				fprintf(F, "%s%s", *tmpv, *(tmpv + 1) ? " " : "");
		fprintf(F, "</td></tr>");
	}

	fprintf(F, "</table></body></html>");

	fclose(F);
}

static void dump_job_state(int fd, struct initng_job *j)
{
	struct initng_job_fd *jfd;
	initng_err_t ingerr;
	
	TAILQ_FOREACH(jfd, &j->thefds, tqe) {
		char *fdstr = NULL;
		asprintf(&fdstr, "%d", jfd->fd);
		ingerr = initng_sendmsg(fd, "addFD", j->label, jfd->label, fdstr, NULL);
		free(fdstr);
		if (ingerr != INITNG_ERR_SUCCESS)
			return initngd_debug(LOG_DEBUG, "failed to send fd %d: %s", jfd->fd, initng_strerror(ingerr));
	}
	ingerr = initng_sendmsg(fd, "dumpJobStateDONE", j->label, NULL);
	if (ingerr != INITNG_ERR_SUCCESS)
		initngd_debug(LOG_DEBUG, "failed to send completion of dumpJobState: %s", initng_strerror(ingerr));
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
