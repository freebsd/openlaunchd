#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <paths.h>

#include "launch.h"
#include "launch_priv.h"

extern char **environ;

typedef void (*kq_callback)(void *, struct kevent *);

struct jobcb {
	kq_callback kqjob_callback;
	TAILQ_ENTRY(jobcb) tqe;
	launch_data_t ldj;
	bool checkedin;
	bool suspended;
	bool has_fds;
	pid_t p;
};

struct usercb {
	TAILQ_ENTRY(usercb) tqe;
	uid_t u;
	bool batch_suspended;
	launch_data_t uenv;
	TAILQ_HEAD(userjobs, jobcb) ujobs;
};

struct conncb {
	kq_callback kqconn_callback;
	TAILQ_ENTRY(conncb) tqe;
	launch_t conn;
	struct jobcb *j;
	uid_t u;
	gid_t g;
};

static TAILQ_HEAD(usercbhead, usercb) users = TAILQ_HEAD_INITIALIZER(users);

static TAILQ_HEAD(conncbhead, conncb) connections = TAILQ_HEAD_INITIALIZER(connections);

static mode_t ourmask = 0;
static int mainkq = 0;

static void job_watch_fds(launch_data_t o, void *cookie);
static void job_ignore_fds(launch_data_t o, void *cookie);
static launch_data_t load_job(launch_data_t pload, struct conncb *c);
static launch_data_t get_jobs(struct userjobs *uhead);
static launch_data_t batch_job_disable(struct usercb *u, bool e);
static struct usercb *find_usercb(uid_t u);
static struct userjobs *find_jobq(uid_t u);
static void ipc_close(struct conncb *c);

static void listen_callback(void *, struct kevent *);
static kq_callback kqlisten_callback = listen_callback;

static void simple_zombie_reaper(void *, struct kevent *);
static kq_callback kqsimple_zombie_reaper = simple_zombie_reaper;

static void job_waitpid(struct jobcb *j);
static void job_event_callback(void *obj, struct kevent *kev);
static int launchd_server_init(const char *);
static void ipc_callback(void *, struct kevent *);
static void ipc_readmsg(launch_data_t msg, void *context);
static void usage(FILE *where, const char *argv0) __attribute__((noreturn));
static void launchd_debug(int priority, const char *format, ...) __attribute__((format(printf,2,3)));
static void launchd_panic(const char *format, ...) __attribute__((noreturn, format(printf,1,2)));
static int __kevent(int q, uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, kq_callback *cback);
static int _fd(int fd);

int main(int argc, char *argv[])
{
	int thesocket;
	struct kevent kev;
	char *thesockpath = NULL;
	int tmpfd, ch, debug = 0;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	ourmask = umask(0);
	umask(ourmask);

	while ((ch = getopt(argc, argv, "dhs:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 's':
			thesockpath = optarg;
			break;
		case 'h':
			usage(stdout, argv[0]);
			break;
		case '?':
		default:
			usage(stderr, argv[0]);
			break;
		}
	}

	openlog(basename(argv[0]), LOG_CONS|(debug ? LOG_PERROR : 0), LOG_DAEMON);

	if ((thesocket = _fd(launchd_server_init(thesockpath))) == -1)
		launchd_panic("launch_server_init(): %m");

	if (!debug) {
		if (getpid() > 1) {
			switch (fork()) {
			case -1:
				launchd_panic("fork(): %m");
			default:
				exit(EXIT_SUCCESS);
			case 0:
				break;
			}
		}
		tmpfd = open(_PATH_DEVNULL, O_RDWR);
		dup2(tmpfd, STDIN_FILENO);
		dup2(tmpfd, STDOUT_FILENO);
		dup2(tmpfd, STDERR_FILENO);
		close(tmpfd);
	}

	chdir("/");
	setsid();

	if ((mainkq = kqueue()) == -1)
		launchd_panic("kqueue(): %m");

	__kevent(mainkq, thesocket, EVFILT_READ, EV_ADD, 0, 0, &kqlisten_callback);

	for (;;) {
		switch (kevent(mainkq, NULL, 0, &kev, 1, NULL)) {
		case -1:
			launchd_debug(LOG_DEBUG, "kevent(): %m");
			continue;
		case 0:
			launchd_debug(LOG_DEBUG, "kevent(): spurious return with infinite timeout");
			continue;
		default:
			break;
		}
		(*((kq_callback *)kev.udata))(kev.udata, &kev);
	}
}

static int launchd_server_init(const char *thepath)
{
        struct sockaddr_un sun;
        char *where = getenv(LAUNCHD_SOCKET_ENV);
        mode_t oldmask = 0;
        int fd;

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        strncpy(sun.sun_path, thepath ? thepath : where ? where : LAUNCHD_DEFAULT_SOCK_PATH, sizeof(sun.sun_path));

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

static long long job_get_integer(launch_data_t j, const char *key)
{
	launch_data_t t = launch_data_dict_lookup(j, key);
	if (t)
		return launch_data_get_integer(t);
	else
		return 0;
}

static const char *job_get_string(launch_data_t j, const char *key)
{
	launch_data_t t = launch_data_dict_lookup(j, key);
	if (t)
		return launch_data_get_string(t);
	else
		return NULL;
}

static const char *job_get_argv0(launch_data_t j)
{
	launch_data_t tmpi, tmp = launch_data_dict_lookup(j, LAUNCH_JOBKEY_PROGRAM);

	if (tmp) {
		return launch_data_get_string(tmp);
	} else {
		tmp = launch_data_dict_lookup(j, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
		if (tmp) {
			tmpi = launch_data_array_get_index(tmp, 0);
			if (tmpi)
				return launch_data_get_string(tmpi);
		}
		return NULL;
	}
}

static bool job_get_bool(launch_data_t j, const char *key)
{
	launch_data_t t = launch_data_dict_lookup(j, key);
	if (t)
		return launch_data_get_bool(t);
	else
		return false;
}

static void ipc_open(int fd, struct jobcb *j)
{
	struct xucred cr;
	struct conncb *c = calloc(1, sizeof(struct conncb));
	int crlen = sizeof(cr);

	fcntl(fd, F_SETFL, O_NONBLOCK);

	if (j) {
		c->u = job_get_integer(j->ldj, LAUNCH_JOBKEY_UID);
		c->g = job_get_integer(j->ldj, LAUNCH_JOBKEY_GID);
	} else if (getsockopt(fd, LOCAL_PEERCRED, 1, &cr, &crlen) == -1) {
		free(c);
		close(fd);
	} else {
		c->u = cr.cr_uid;
		c->g = cr.cr_gid;
	}

        c->kqconn_callback = ipc_callback;
        c->conn = launchd_fdopen(fd);
        c->j = j;
	TAILQ_INSERT_TAIL(&connections, c, tqe);
	__kevent(mainkq, fd, EVFILT_READ, EV_ADD, 0, 0, &c->kqconn_callback);
}

static void simple_zombie_reaper(void *obj __attribute__((unused)), struct kevent *kev)
{
	int status;

	waitpid(kev->ident, &status, 0);
}

static void listen_callback(void *obj __attribute__((unused)), struct kevent *kev)
{
        struct sockaddr_un sun;
        socklen_t sl = sizeof(sun);
        int cfd;

        if ((cfd = _fd(accept(kev->ident, (struct sockaddr *)&sun, &sl))) == -1) {
                return;
	}

	ipc_open(cfd, NULL);
}

static void ipc_callback(void *obj, struct kevent *kev)
{
	struct conncb *c = obj;
	int r;

	if (kev->filter == EVFILT_READ) {
		if (launchd_msg_recv(c->conn, ipc_readmsg, c) == -1 && errno != EAGAIN) {
			if (errno != ECONNRESET)
				launchd_debug(LOG_DEBUG, "%s(): read: %m", __func__);
			ipc_close(c);
		}
	} else if (kev->filter == EVFILT_WRITE) {
		r = launchd_msg_send(c->conn, NULL);
		if (r == -1) {
			if (errno != EAGAIN) {
				launchd_debug(LOG_DEBUG, "%s(): send: %m", __func__);
				ipc_close(c);
			}
		} else if (r == 0) {
			__kevent(mainkq, launchd_getfd(c->conn), EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		}
	} else {
		launchd_debug(LOG_DEBUG, "%s(): unknown filter type!", __func__);
		ipc_close(c);
	}
}

static void set_user_env(launch_data_t obj, const char *key, void *context)
{
	struct usercb *u = context;

	launch_data_dict_insert(u->uenv, launch_data_copy(obj), key);
}

static void launch_data_close_fds(launch_data_t o)
{
	size_t i;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, (void (*)(launch_data_t, const char *, void *))launch_data_close_fds, NULL);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			launch_data_close_fds(launch_data_array_get_index(o, i));
		break;
	case LAUNCH_DATA_FD:
		close(launch_data_get_fd(o));
		break;
	default:
		break;
	}
}

static void job_ignore_fds_dict(launch_data_t o, const char *k __attribute__((unused)), void *cookie)
{
	job_ignore_fds(o, cookie);
}

static void job_ignore_fds(launch_data_t o, void *cookie)
{
	size_t i;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, job_ignore_fds_dict, cookie);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			job_ignore_fds(launch_data_array_get_index(o, i), cookie);
		break;
	case LAUNCH_DATA_FD:
		__kevent(mainkq, launch_data_get_fd(o), EVFILT_READ, EV_DELETE, 0, 0, cookie);
		break;
	default:
		break;
	}
}

static void job_watch_fds_dict(launch_data_t o, const char *k __attribute__((unused)), void *cookie)
{
	job_watch_fds(o, cookie);
}

static void job_watch_fds(launch_data_t o, void *cookie)
{
	size_t i;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, job_watch_fds_dict, cookie);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			job_watch_fds(launch_data_array_get_index(o, i), cookie);
		break;
	case LAUNCH_DATA_FD:
		__kevent(mainkq, launch_data_get_fd(o), EVFILT_READ, EV_ADD, 0, 0, cookie);
		break;
	default:
		break;
	}
}

static void job_remove(struct jobcb *j)
{
	TAILQ_REMOVE(find_jobq(job_get_integer(j->ldj, LAUNCH_JOBKEY_UID)), j, tqe);
        if (j->p) {
        	if (__kevent(mainkq, j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) == -1) {
        		job_waitpid(j);
		} else {
			kill(j->p, SIGTERM);
		}
	}
	launch_data_close_fds(j->ldj);
	launch_data_free(j->ldj);
	free(j);
}

static void ipc_readmsg(launch_data_t msg, void *context)
{
	char uidstr[64];
	struct conncb *c = context;
	struct usercb *u = find_usercb(c->u);
	struct jobcb *j;
	launch_data_t pload, tmp, resp = NULL;
	size_t i;

	if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) &&
			(tmp = launch_data_dict_lookup(msg, LAUNCH_KEY_REMOVEJOB))) {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		TAILQ_FOREACH(j, find_jobq(c->u), tqe) {
			if (!strcmp(job_get_string(j->ldj, LAUNCH_JOBKEY_LABEL), launch_data_get_string(tmp))) {
				job_remove(j);
				launch_data_set_string(resp, LAUNCH_RESPONSE_SUCCESS);
				goto out;
			}
		}
		launch_data_set_string(resp, LAUNCH_RESPONSE_JOBNOTFOUND);
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) &&
			(pload = launch_data_dict_lookup(msg, LAUNCH_KEY_SUBMITJOBS))) {
		resp = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (i = 0; i < launch_data_array_get_count(pload); i++) {
			tmp = load_job(launch_data_array_get_index(pload, i), c);
			launch_data_array_set_index(resp, tmp, i);
		}
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) &&
			(pload = launch_data_dict_lookup(msg, LAUNCH_KEY_SUBMITJOB))) {
		resp = load_job(pload, c);
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) &&
			(pload = launch_data_dict_lookup(msg, LAUNCH_KEY_UNSETUSERENVIRONMENT))) {
		launch_data_dict_remove(u->uenv, launch_data_get_string(pload));
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, LAUNCH_RESPONSE_SUCCESS);
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) &&
			!strcmp(launch_data_get_string(msg), LAUNCH_KEY_GETUSERENVIRONMENT)) {
		resp = launch_data_copy(u->uenv);
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) &&
			(pload = launch_data_dict_lookup(msg, LAUNCH_KEY_SETUSERENVIRONMENT))) {
		launch_data_dict_iterate(pload, set_user_env, u);
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, LAUNCH_RESPONSE_SUCCESS);
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) &&
			!strcmp(launch_data_get_string(msg), LAUNCH_KEY_CHECKIN)) {
		if (c->j) {
			resp = launch_data_copy(c->j->ldj);
			c->j->checkedin = true;
		} else {
			resp = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(resp, LAUNCH_RESPONSE_NOTRUNNINGFROMLAUNCHD);
		}
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) &&
			!strcmp(launch_data_get_string(msg), LAUNCH_KEY_GETJOBS)) {
		resp = get_jobs(find_jobq(c->u));
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) &&
			!strcmp(launch_data_get_string(msg), LAUNCH_KEY_GETAllJOBS)) {
		resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		TAILQ_FOREACH(u, &users, tqe) {
			sprintf(uidstr, "%d", u->u);
			launch_data_dict_insert(resp, get_jobs(&u->ujobs), uidstr);
		}
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) &&
			(tmp = launch_data_dict_lookup(msg, LAUNCH_KEY_BATCHCONTROL))) {
		resp = batch_job_disable(u, launch_data_get_bool(tmp));
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) &&
			!strcmp(launch_data_get_string(msg), LAUNCH_KEY_BATCHQUERY)) {
		resp = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(resp, !u->batch_suspended);
	} else {	
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, LAUNCH_RESPONSE_UNKNOWNCOMMAND);
	}
out:
	if (launchd_msg_send(c->conn, resp) == -1) {
		if (errno == EAGAIN) {
			__kevent(mainkq, launchd_getfd(c->conn), EVFILT_WRITE, EV_ADD, 0, 0, &c->kqconn_callback);
		} else {
			launchd_debug(LOG_DEBUG, "launchd_msg_send() == -1: %m");
			ipc_close(c);
		}
	}
	launch_data_free(resp);
}

static launch_data_t batch_job_disable(struct usercb *u, bool e)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_STRING);
	struct jobcb *j;

	launch_data_set_string(resp, LAUNCH_RESPONSE_SUCCESS);

	if (e) {
		u->batch_suspended = true;
		TAILQ_FOREACH(j, &u->ujobs, tqe) {
			if (job_get_bool(j->ldj, LAUNCH_JOBKEY_BATCH) && !j->suspended) {
				j->suspended = true;
				job_ignore_fds(j->ldj, &j->kqjob_callback);
				if (j->p)
					kill(j->p, SIGSTOP);
			}
		}
	} else {
		u->batch_suspended = false;
		TAILQ_FOREACH(j, &u->ujobs, tqe) {
			if (job_get_bool(j->ldj, LAUNCH_JOBKEY_BATCH) && j->suspended) {
				j->suspended = false;
				job_watch_fds(j->ldj, &j->kqjob_callback);
				if (j->p)
					kill(j->p, SIGCONT);
			}
		}
	}

	return resp;
}

static launch_data_t load_job(launch_data_t pload, struct conncb *c)
{
	launch_data_t tmp, resp;
	struct jobcb *j;
	struct usercb *u = find_usercb(c->u);

	if ((tmp = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_LABEL))) {
		TAILQ_FOREACH(j, &u->ujobs, tqe) {
			if (!strcmp(job_get_string(j->ldj, LAUNCH_JOBKEY_LABEL), launch_data_get_string(tmp))) {
				resp = launch_data_alloc(LAUNCH_DATA_STRING);
				launch_data_set_string(resp, LAUNCH_RESPONSE_JOBEXISTS);
				goto out;
			}
		}
	} else {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, LAUNCH_RESPONSE_LABELMISSING);
		goto out;
	}
	if (launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAMARGUMENTS) == NULL) {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, LAUNCH_RESPONSE_PROGRAMARGUMENTSMISSING);
		goto out;
	}

	j = calloc(1, sizeof(struct jobcb));
	j->ldj = launch_data_copy(pload);
	j->kqjob_callback = job_event_callback;

	if (c->u != 0) {
		tmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmp, c->u);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_UID);

		tmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmp, c->g);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_GID);

		launch_data_dict_remove(j->ldj, LAUNCH_JOBKEY_ROOT);
	}
	
	if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_ONDEMAND) == NULL) {
		tmp = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(tmp, true);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_ONDEMAND);
	}

	TAILQ_INSERT_TAIL(find_jobq(c->u), j, tqe);

	if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
		job_watch_fds(j->ldj, &j->kqjob_callback);
	else
		job_event_callback(j, NULL);

	resp = launch_data_alloc(LAUNCH_DATA_STRING);
	launch_data_set_string(resp, LAUNCH_RESPONSE_SUCCESS);
out:
	return resp;
}

static launch_data_t get_jobs(struct userjobs *uhead)
{
	struct jobcb *j;
	launch_data_t tmp, resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	TAILQ_FOREACH(j, uhead, tqe) {
		tmp = launch_data_copy(j->ldj);
		launch_data_dict_insert(resp, tmp, job_get_string(j->ldj, LAUNCH_JOBKEY_LABEL));
	}

	return resp;
}

static void launchd_panic(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsyslog(LOG_EMERG, format, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void launchd_debug(int priority, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsyslog(priority, format, ap);
	va_end(ap);
}

static void usage(FILE *where, const char *argv0)
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

static int __kevent(int q, uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, kq_callback *cback)
{
	struct kevent kev;
	EV_SET(&kev, ident, filter, flags, fflags, data, cback);
	return kevent(q, &kev, 1, NULL, 0, NULL);
}

static int _fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}

static void ipc_close(struct conncb *c)
{
	struct usercb *u = find_usercb(c->u);

	launch_data_free(batch_job_disable(u, false));

	TAILQ_REMOVE(&connections, c, tqe);
	launchd_close(c->conn);
	free(c);
}

static struct usercb *find_usercb(uid_t u)
{
	struct usercb *ucb;

	TAILQ_FOREACH(ucb, &users, tqe) {
		if (ucb->u == u)
			goto out;
	}

	ucb = calloc(1, sizeof(struct usercb));
	ucb->u = u;
	ucb->uenv = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	TAILQ_INIT(&ucb->ujobs);
	TAILQ_INSERT_TAIL(&users, ucb, tqe);
out:
	return ucb;
}

static struct userjobs *find_jobq(uid_t u)
{
	struct usercb *ucb = find_usercb(u);

	return &ucb->ujobs;
}

static void setup_job_env(launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	if (LAUNCH_DATA_STRING == launch_data_get_type(obj))
		setenv(key, launch_data_get_string(obj), 1);
}

static void job_waitpid(struct jobcb *j)
{
	int status;

	waitpid(j->p, &status, 0);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) > 0)
			launchd_debug(LOG_WARNING, "%s[%d] exited with exit code %d",
					job_get_argv0(j->ldj), j->p, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		launchd_debug(LOG_WARNING, "%s[%d] exited abnormally with signal %d",
					job_get_argv0(j->ldj), j->p, WTERMSIG(status));
	}

	j->p = 0;
}

static void job_event_callback(void *obj, struct kevent *kev)
{
	char nbuf[64];
	struct jobcb *j = obj;
        pid_t c;
	int spair[2];
	const char **argv;

	if (kev && kev->filter == EVFILT_PROC) {
		job_waitpid(j);

		if (j->checkedin != true && j->has_fds) {
			job_remove(j);
			return;
		}
		if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND)) {
			job_watch_fds(j->ldj, &j->kqjob_callback);
			return;
		}
	}

	socketpair(AF_UNIX, SOCK_STREAM, 0, spair);

        if ((c = fork()) == -1) {
                launchd_debug(LOG_DEBUG, "fork(): %m");
                return;
        } else if (c == 0) {
		launch_data_t ldpa = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
		size_t i, argv_cnt;

		argv_cnt = launch_data_array_get_count(ldpa);
		argv = alloca((argv_cnt + 1) * sizeof(char *));
		for (i = 0; i < argv_cnt; i++)
			argv[i] = launch_data_get_string(launch_data_array_get_index(ldpa, i));
		argv[argv_cnt] = NULL;

		close(spair[0]);
		if (job_get_string(j->ldj, LAUNCH_JOBKEY_ROOT))
			chroot(job_get_string(j->ldj, LAUNCH_JOBKEY_ROOT));
		if (job_get_integer(j->ldj, LAUNCH_JOBKEY_GID) != getegid())
			setgid(job_get_integer(j->ldj, LAUNCH_JOBKEY_GID));
		if (job_get_integer(j->ldj, LAUNCH_JOBKEY_UID) != geteuid())
			setuid(job_get_integer(j->ldj, LAUNCH_JOBKEY_UID));
		if (job_get_string(j->ldj, LAUNCH_JOBKEY_WORKINGDIRECTORY))
			chdir(job_get_string(j->ldj, LAUNCH_JOBKEY_WORKINGDIRECTORY));
		if (job_get_integer(j->ldj, LAUNCH_JOBKEY_UMASK) != ourmask)
			umask(job_get_integer(j->ldj, LAUNCH_JOBKEY_UMASK));
		sprintf(nbuf, "%d", spair[1]);
#ifdef FIXME
		launch_data_dict_iterate(j->uenv, setup_job_env, NULL);
#endif
		if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES))
			launch_data_dict_iterate(launch_data_dict_lookup(j->ldj,
						LAUNCH_JOBKEY_ENVIRONMENTVARIABLES),
					setup_job_env, NULL);
		setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
                setsid();
                if (execvp(job_get_argv0(j->ldj), (char *const*)argv) == -1)
                        launchd_debug(LOG_DEBUG, "child execvp(): %m");
		sleep(1);
                _exit(EXIT_FAILURE);
        }
	close(spair[1]);
	ipc_open(spair[0], j);

        if (__kevent(mainkq, c, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &j->kqjob_callback) == -1) {
                launchd_debug(LOG_DEBUG, "kevent(): %m");
                return;
        } else {
	        j->p = c;
	        j->checkedin = false;
		if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
			job_ignore_fds(j->ldj, j->kqjob_callback);
	}
}
