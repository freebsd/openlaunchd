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

#include "launch.h"
#include "launch_priv.h"

extern char **environ;

typedef void (*kq_callback)(void *, struct kevent *);

struct evsourcecb {
	TAILQ_ENTRY(evsourcecb) tqe;
	char *key;
	size_t count;
	int fds[0];
};

struct jobcb {
	kq_callback kqjob_callback;
	TAILQ_ENTRY(jobcb) tqe;
	bool od;
	int kq;
	pid_t p;
	uid_t u;
	gid_t g;
	mode_t m;
	char *wd;
	char *prog;
	char *label;
	char *desc;
	char *root;
	const char **argv;
	launch_data_t env;
	TAILQ_HEAD(evsources, evsourcecb) evs;
	launch_data_t uenv;
};

struct usercb {
	TAILQ_ENTRY(usercb) tqe;
	uid_t u;
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

static launch_data_t load_job(launch_data_t pload, struct conncb *c);
static void free_stray_fds(launch_data_t o);
static launch_data_t get_jobs(struct userjobs *uhead);
static struct usercb *find_usercb(uid_t u);
static struct userjobs *find_jobq(uid_t u);
static void ipc_close(struct conncb *c);

static void listen_callback(void *, struct kevent *);
static kq_callback kqlisten_callback = listen_callback;

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
		tmpfd = open("/dev/null", O_RDWR);
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
		if (kevent(mainkq, NULL, 0, &kev, 1, NULL) == -1) {
			launchd_debug(LOG_DEBUG, "kevent(): %m");
			continue;
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
        strncpy(sun.sun_path, thepath ? thepath : where ? where : "/var/run/launchd.socket", sizeof(sun.sun_path));

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

static void ipc_open(int fd, struct jobcb *j)
{
	struct xucred cr;
	struct conncb *c = calloc(1, sizeof(struct conncb));
	int crlen = sizeof(cr);

	fcntl(fd, F_SETFL, O_NONBLOCK);

	if (j) {
		c->u = j->u;
		c->g = j->g;
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

static void job_addevs(launch_data_t val, const char *key, void *obj)
{
	struct jobcb *j = obj;
	struct evsourcecb *ev = NULL;
	launch_data_t tmpi;
	size_t i;

	if (LAUNCH_DATA_ARRAY == launch_data_get_type(val)) {
		ev = malloc(sizeof(struct evsourcecb) + sizeof(int) * launch_data_array_get_count(val));
		ev->key = strdup(key);
		ev->count = launch_data_array_get_count(val);

		for (i = 0; i < ev->count; i++) {
			tmpi = launch_data_array_get_index(val, i);
			ev->fds[i] = _fd(launch_data_get_fd(tmpi));
			launch_data_set_fd(tmpi, -1);
			if (j->od && __kevent(j->kq, ev->fds[i], EVFILT_READ, EV_ADD, 0, 0, &j->kqjob_callback) == -1)
				launchd_debug(LOG_DEBUG, "%s(): kevent(): %m", __func__);
		}
	} else if (LAUNCH_DATA_FD == launch_data_get_type(val)) {
		ev = malloc(sizeof(struct evsourcecb) + sizeof(int));
		ev->key = strdup(key);
		ev->count = 1;
		ev->fds[0] = _fd(launch_data_get_fd(val));
		launch_data_set_fd(val, -1);
	}

	if (ev)
		TAILQ_INSERT_TAIL(&j->evs, ev, tqe);
}

static launch_data_t evs2launch_data(struct jobcb *j)
{
	struct evsourcecb *ev;
	size_t i;
	launch_data_t tmp, tmpi, resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	TAILQ_FOREACH(ev, &j->evs, tqe) {
		tmp = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (i = 0; i < ev->count; i++) {
			tmpi = launch_data_alloc(LAUNCH_DATA_FD);
			launch_data_set_fd(tmpi, ev->fds[i]);
			launch_data_array_set_index(tmp, tmpi, i);
		}
		launch_data_dict_insert(resp, tmp, ev->key);
	}
	return resp;
}

static void set_user_env(launch_data_t obj, const char *key, void *context)
{
	struct usercb *u = context;

	launch_data_dict_insert(u->uenv, launch_data_copy(obj), key);
}

static void ipc_readmsg(launch_data_t msg, void *context)
{
	char uidstr[64];
	struct conncb *c = context;
	struct evsourcecb *ev;
	struct usercb *u;
	struct jobcb *j;
	launch_data_t pload, tmp, resp = NULL;
	size_t i;
	const char **argvtmp;

	if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) && (tmp = launch_data_dict_lookup(msg, "RemoveJob"))) {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		TAILQ_FOREACH(j, find_jobq(c->u), tqe) {
			if (!strcmp(j->label, launch_data_get_string(tmp))) {
				TAILQ_REMOVE(find_jobq(c->u), j, tqe);
				if (j->kq != -1)
					close(j->kq);
				if (j->p)
        				__kevent(mainkq, j->p, EVFILT_PROC, EV_DELETE, NOTE_EXIT, 0, &j->kqjob_callback);
				if (j->wd)
					free(j->wd);
				if (j->root)
					free(j->root);
				if (j->prog)
					free(j->prog);
				free(j->label);
				if (j->desc)
					free(j->desc);
				for (argvtmp = j->argv; *argvtmp; argvtmp++)
					free((char *)*argvtmp);
				free(j->argv);
				if (j->env)
					launch_data_free(j->env);
				while ((ev = TAILQ_FIRST(&j->evs))) {
					TAILQ_REMOVE(&j->evs, ev, tqe);
					for (i = 0; i < ev->count; i++)
        					close(ev->fds[i]);
					free(ev->key);
					free(ev);
				}
				free(j);

				launch_data_set_string(resp, "Success");
				goto out;
			}
		}
		launch_data_set_string(resp, "JobNotFound");
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) && (pload = launch_data_dict_lookup(msg, "SubmitJobs"))) {
		resp = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (i = 0; i < launch_data_array_get_count(pload); i++) {
			tmp = load_job(launch_data_array_get_index(pload, i), c);
			launch_data_array_set_index(resp, tmp, i);
		}
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) && (pload = launch_data_dict_lookup(msg, "SubmitJob"))) {
		resp = load_job(pload, c);
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) && (pload = launch_data_dict_lookup(msg, "UnsetUserEnvironment"))) {
		launch_data_dict_remove(find_usercb(c->u)->uenv, launch_data_get_string(pload));
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, "Success");
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) && !strcmp(launch_data_get_string(msg), "GetUserEnvironment")) {
		resp = launch_data_copy(find_usercb(c->u)->uenv);
	} else if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) && (pload = launch_data_dict_lookup(msg, "SetUserEnvironment"))) {
		launch_data_dict_iterate(pload, set_user_env, find_usercb(c->u));
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, "Success");
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) && !strcmp(launch_data_get_string(msg), "CheckIn")) {
		if (c->j) {
			resp = evs2launch_data(c->j);
		} else {
			resp = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(resp, "NotRunningFromLaunchd");
		}
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) && !strcmp(launch_data_get_string(msg), "GetJobs")) {
		resp = get_jobs(find_jobq(c->u));
	} else if ((LAUNCH_DATA_STRING == launch_data_get_type(msg)) && !strcmp(launch_data_get_string(msg), "GetAllJobs")) {
		resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		TAILQ_FOREACH(u, &users, tqe) {
			sprintf(uidstr, "%d", u->u);
			launch_data_dict_insert(resp, get_jobs(&u->ujobs), uidstr);
		}
	} else {	
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, "UnknownCommand");
	}
out:
	free_stray_fds(msg);
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

static launch_data_t load_job(launch_data_t pload, struct conncb *c)
{
	bool od = true;
	launch_data_t tmp, tmpi, resp;
	struct jobcb *j;
	size_t i;

	if ((tmp = launch_data_dict_lookup(pload, "Label"))) {
		TAILQ_FOREACH(j, find_jobq(c->u), tqe) {
			if (!strcmp(j->label, launch_data_get_string(tmp))) {
				resp = launch_data_alloc(LAUNCH_DATA_STRING);
				launch_data_set_string(resp, "JobExists");
				goto out;
			}
		}
	} else {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, "LabelMissing");
		goto out;
	}
	if (launch_data_dict_lookup(pload, "ProgramArguments") == NULL) {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, "ProgramArgumentsMissing");
		goto out;
	}
	if ((tmp = launch_data_dict_lookup(pload, "OnDemand")))
		od = launch_data_get_bool(tmp);
	if (launch_data_dict_lookup(pload, "EventSources") == NULL && od) {
		resp = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(resp, "MissingEventSources");
		goto out;
	}
	j = calloc(1, sizeof(struct jobcb));
	TAILQ_INIT(&j->evs);
	j->od = od;
	j->kq = od ? kqueue() : -1;
	j->kqjob_callback = job_event_callback;
	j->uenv = find_usercb(c->u)->uenv;

	if (c->u == 0) {
		if ((tmp = launch_data_dict_lookup(pload, "UID")))
			j->u = (uid_t)launch_data_get_integer(tmp);
		if ((tmp = launch_data_dict_lookup(pload, "GID")))
			j->g = (uid_t)launch_data_get_integer(tmp);
		if ((tmp = launch_data_dict_lookup(pload, "Root")))
			j->root = strdup(launch_data_get_string(tmp));
	} else {
		j->u = c->u;
		j->g = c->g;
	}
	if ((tmp = launch_data_dict_lookup(pload, "WorkingDirectory")))
		j->wd = strdup(launch_data_get_string(tmp));
	if ((tmp = launch_data_dict_lookup(pload, "Label")))
		j->label = strdup(launch_data_get_string(tmp));
	if ((tmp = launch_data_dict_lookup(pload, "ServiceDescription")))
		j->desc = strdup(launch_data_get_string(tmp));
	if ((tmp = launch_data_dict_lookup(pload, "Program")))
		j->prog = strdup(launch_data_get_string(tmp));
	if ((tmp = launch_data_dict_lookup(pload, "EnvironmentVariables")))
		j->env = launch_data_copy(tmp);
	if ((tmp = launch_data_dict_lookup(pload, "ProgramArguments"))) {
		j->argv = malloc(sizeof(char *) * (launch_data_array_get_count(tmp) + 1));
		for (i = 0; i < launch_data_array_get_count(tmp); i++) {
			tmpi = launch_data_array_get_index(tmp, i);
			j->argv[i] = strdup(launch_data_get_string(tmpi));
		}
		j->argv[launch_data_array_get_count(tmp)] = NULL;
	}
	if ((tmp = launch_data_dict_lookup(pload, "EventSources")))
		launch_data_dict_iterate(tmp, job_addevs, j);

	TAILQ_INSERT_TAIL(find_jobq(c->u), j, tqe);

	if (j->od)
		__kevent(mainkq, j->kq, EVFILT_READ, EV_ADD, 0, 0, &j->kqjob_callback);
	else
		job_event_callback(j, NULL);

	resp = launch_data_alloc(LAUNCH_DATA_STRING);
	launch_data_set_string(resp, "Success");
out:
	return resp;
}

static void free_stray_fds(launch_data_t o)
{
	int fd;
	size_t i;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_FD:
		if ((fd = launch_data_get_fd(o)) != -1)
			close(fd);
		break;
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			free_stray_fds(launch_data_array_get_index(o, i));
		break;
	default:
		break;
	}
}

static launch_data_t get_jobs(struct userjobs *uhead)
{
	const char **argvtmp;
	struct jobcb *j;
	launch_data_t tmp, tmpi, tmpa, resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	TAILQ_FOREACH(j, uhead, tqe) {
		tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

		tmpi = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(tmpi, j->od);
		launch_data_dict_insert(tmp, tmpi, "OnDemand");

		if (j->p != 0) {
			tmpi = launch_data_alloc(LAUNCH_DATA_INTEGER);
			launch_data_set_integer(tmpi, j->p);
			launch_data_dict_insert(tmp, tmpi, "PID");
		}

		tmpi = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmpi, j->m);
		launch_data_dict_insert(tmp, tmpi, "Umask");

		if (j->wd) {
			tmpi = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(tmpi, j->wd);
			launch_data_dict_insert(tmp, tmpi, "WorkingDirectory");
		}

		if (j->root) {
			tmpi = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(tmpi, j->root);
			launch_data_dict_insert(tmp, tmpi, "Root");
		}

		tmpi = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (argvtmp = j->argv; *argvtmp; argvtmp++) {
			tmpa = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(tmpa, *argvtmp);
			launch_data_array_set_index(tmpi, tmpa, launch_data_array_get_count(tmpi));
		}
		launch_data_dict_insert(tmp, tmpi, "ProgramArguments");

		tmpi = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmpi, j->u);
		launch_data_dict_insert(tmp, tmpi, "UID");

		tmpi = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmpi, j->g);
		launch_data_dict_insert(tmp, tmpi, "GID");

		if (j->prog) {
			tmpi = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(tmpi, j->prog);
			launch_data_dict_insert(tmp, tmpi, "Program");
		}

		if (j->desc) {
			tmpi = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(tmpi, j->desc);
			launch_data_dict_insert(tmp, tmpi, "ServiceDescription");
		}

		if (j->env)
			launch_data_dict_insert(tmp, launch_data_copy(j->env), "EnvironmentVariables");

		launch_data_dict_insert(tmp, evs2launch_data(j), "EventSources");

		launch_data_dict_insert(resp, tmp, j->label);
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

	ucb = malloc(sizeof(struct usercb));
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

static void job_event_callback(void *obj, struct kevent *kev)
{
	struct timespec tout = { 0, 0 };
	struct kevent tmpkev;
	char nbuf[64];
	struct jobcb *j = obj;
        pid_t c;
	int status;
	int spair[2];

	if (kev == NULL)
		goto launch_again;

	if (kev->filter == EVFILT_PROC) {
		waitpid(j->p, &status, 0);

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) > 0)
				launchd_debug(LOG_WARNING, "%s[%d] exited with exit code %d", j->prog ? j->prog : j->argv[0], j->p, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			launchd_debug(LOG_WARNING, "%s[%d] exited abnormally with signal %d", j->prog ? j->prog : j->argv[0], j->p, WTERMSIG(status));
		}

		j->p = 0;
		if (j->od)
			__kevent(mainkq, j->kq, EVFILT_READ, EV_ADD, 0, 0, &j->kqjob_callback);
		/* ah, the fun of kqueues
		 *
		 * events queued for delivery are checked for validity before actual delivery
		 *
		 * launchd is a bit weird, we don't actually need to call kevent on the sub-kqueue
		 * but if we don't those queued events still cause the sub kqueue to count as
		 * readable in the main kqueue, thus the following code to return the sub-kqueue
		 * back to "no pending events" from the main kqueue's perspective
		 */
		if (j->od) {
			if (kevent(j->kq, NULL, 0, &tmpkev, 1, &tout) > 0)
				goto launch_again;
		} else
			goto launch_again;
		return;
	}
launch_again:

	socketpair(AF_UNIX, SOCK_STREAM, 0, spair);

        if ((c = fork()) == -1) {
                launchd_debug(LOG_DEBUG, "fork(): %m");
                return;
        } else if (c == 0) {
		close(spair[0]);
		if (j->root)
			chroot(j->root);
		if (j->g != getegid())
			setgid(j->g);
		if (j->u != geteuid())
			setuid(j->u);
		if (j->wd)
			chdir(j->wd);
		if (j->m != ourmask)
			umask(j->m);
		sprintf(nbuf, "%d", spair[1]);
		launch_data_dict_iterate(j->uenv, setup_job_env, NULL);
		if (j->env)
			launch_data_dict_iterate(j->env, setup_job_env, NULL);
		setenv("__LAUNCHD_FD", nbuf, 1);
                setsid();
                if (execvp(j->prog ? j->prog : j->argv[0], (char * const*)j->argv) == -1)
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
		if (j->od)
			__kevent(mainkq, j->kq, EVFILT_READ, EV_DELETE, 0, 0, &j->kqjob_callback);
	}
}
