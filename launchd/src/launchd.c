#include <mach/mach_error.h>
#include <mach/port.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>
#include <paths.h>

#include "launch.h"
#include "launch_priv.h"

#include "launchd.h"

#include "bootstrap_internal.h"

extern char **environ;

struct jobcb {
	kq_callback kqjob_callback;
	TAILQ_ENTRY(jobcb) tqe;
	launch_data_t ldj;
	bool checkedin;
	bool suspended;
	pid_t p;
	int wstatus;
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
int mainkq = 0;

static launch_data_t load_job(launch_data_t pload, struct conncb *c);
static launch_data_t get_jobs(struct userjobs *uhead);
static launch_data_t batch_job_disable(struct usercb *u, bool e);

static struct usercb *find_usercb(uid_t u);
static struct userjobs *find_jobq(uid_t u);

static void listen_callback(void *, struct kevent *);
static void signal_callback(void *, struct kevent *);
static void fs_callback(void *, struct kevent *);
static void simple_zombie_reaper(void *, struct kevent *);
static void mach_callback(void *, struct kevent *);

static kq_callback kqlisten_callback = listen_callback;
static kq_callback kqsignal_callback = signal_callback;
static kq_callback kqfs_callback = fs_callback;
static kq_callback kqmach_callback = mach_callback;
kq_callback kqsimple_zombie_reaper = simple_zombie_reaper;

static void job_watch_fds(launch_data_t o, void *cookie);
static void job_ignore_fds(launch_data_t o, void *cookie);
static void job_launch(struct jobcb *j);
static void job_reap(struct jobcb *j);
static void job_remove(struct jobcb *j);
static void job_callback(void *obj, struct kevent *kev);

static void ipc_open(int fd, struct jobcb *j);
static void ipc_close(struct conncb *c);
static void ipc_callback(void *, struct kevent *);
static void ipc_readmsg(launch_data_t msg, void *context);

static bool launchd_check_pid(pid_t p, int status);
static int launchd_server_init(char *);

static void *mach_demand_loop(void *);

static void usage(FILE *where);
static int _fd(int fd);

static void dummysignalhandler(int sig);

static void loopback_setup(void);
static void update_lm(void);
static void workaround3048875(int argc, char *argv[]);

static int thesocket = -1;
static char *thesockpath = NULL;
static bool debug = false;
static bool verbose = false;
static pthread_t mach_server_loop_thread;
mach_port_t launchd_bootstrap_port = MACH_PORT_NULL;

int main(int argc, char *argv[])
{
	pthread_attr_t attr;
	struct kevent kev;
	size_t i;
	bool sflag = false, xflag = false, bflag = false;
	int pthr_r, ch, sigigns[] = { SIGHUP, SIGINT, SIGPIPE, SIGALRM, SIGTERM,
		SIGURG, SIGTSTP, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2 };

	if (getpid() == 1)
		workaround3048875(argc, argv);
	
	ourmask = umask(0);
	umask(ourmask);

	while ((ch = getopt(argc, argv, "dhS:svxb")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		case 's':
			sflag = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'x':
			xflag = true;
			break;
		case 'b':
			bflag = true;
			break;
		case 'S':
			thesockpath = optarg;
			break;
		case 'h':
			usage(stdout);
			break;
		case '?':
		default:
			syslog(LOG_WARNING, "ignoring unknown arguments");
			usage(stderr);
			break;
		}
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	open(_PATH_DEVNULL, O_RDONLY);
	open(_PATH_DEVNULL, O_WRONLY);
	open(_PATH_DEVNULL, O_WRONLY);

	openlog(basename(argv[0]), LOG_CONS|(getpid() != 1 ? LOG_PID|LOG_PERROR : 0), LOG_DAEMON);
	update_lm();
	
	if (getpid() == 1) {
		int memmib[2] = { CTL_HW, HW_PHYSMEM };
		int mvnmib[2] = { CTL_KERN, KERN_MAXVNODES };
		int hnmib[2] = { CTL_KERN, KERN_HOSTNAME };
		uint64_t mem = 0;
		uint32_t mvn;
		size_t memsz = sizeof(mem);
		
		if (sysctl(memmib, 2, &mem, &memsz, NULL, 0) == -1) {
			syslog(LOG_WARNING, "sysctl(\"hw.physmem\"): %m");
		} else {
			/* The following assignment of mem to itself if the size
			 * of data returned is 32 bits instead of 64 is a clever
			 * C trick to move the 32 bits on big endian systems to
			 * the least significant bytes of the 64 mem variable.
			 *
			 * On little endian systems, this is effectively a no-op.
			 */
			if (memsz == 4)
				mem = *(uint32_t *)&mem;
			mvn = mem / (64 * 1024) + 1024;
			if (sysctl(mvnmib, 2, NULL, NULL, &mvn, sizeof(mvn)) == -1)
				syslog(LOG_WARNING, "sysctl(\"kern.maxvnodes\"): %m");
		}
		if (sysctl(hnmib, 2, NULL, NULL, "localhost", sizeof("localhost")) == -1)
			syslog(LOG_WARNING, "sysctl(\"kern.hostname\"): %m");

		if (setlogin("root") == -1)
			syslog(LOG_ERR, "setlogin(\"root\"): %m");

		loopback_setup();
	}

	if ((mainkq = kqueue()) == -1) {
		syslog(LOG_EMERG, "kqueue(): %m");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
		if (kevent_mod(sigigns[i], EVFILT_SIGNAL, EV_ADD, 0, 0, &kqsignal_callback) == -1)
			syslog(LOG_ERR, "failed to add kevent for signal: %d: %m", sigigns[i]);
		signal(sigigns[i], dummysignalhandler);
	}

	setenv("PATH", _PATH_STDPATH, 1);

	if (setsid() == -1)
		syslog(LOG_ERR, "setsid(): %m");

	if (chdir("/") == -1)
		syslog(LOG_ERR, "chdir(\"/\"): %m");

	setpriority(PRIO_PROCESS, 0, -1);

	launchd_bootstrap_port = mach_init_init();
	task_set_bootstrap_port(mach_task_self(), launchd_bootstrap_port);
	bootstrap_port = MACH_PORT_NULL;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthr_r = pthread_create(&mach_server_loop_thread, &attr, mach_server_loop, NULL);
	if (pthr_r != 0) {
		syslog(LOG_ERR, "pthread_create(mach_server_loop): %s", strerror(pthr_r));
		exit(EXIT_FAILURE);
	}

	pthread_attr_destroy(&attr);

	init_boot(sflag, verbose, xflag, bflag);

	if (kevent_mod(0, EVFILT_FS, EV_ADD, 0, 0, &kqfs_callback) == -1)
		syslog(LOG_ERR, "kevent_mod(EVFILT_FS, &kqfs_callback): %m");

	for (;;) {
		init_pre_kevent();

		switch (kevent(mainkq, NULL, 0, &kev, 1, NULL)) {
		case -1:
			syslog(LOG_DEBUG, "kevent(): %m");
			break;
		case 1:
			(*((kq_callback *)kev.udata))(kev.udata, &kev);
			break;
		case 0:
			syslog(LOG_DEBUG, "kevent(): spurious return with infinite timeout");
			break;
		default:
			syslog(LOG_DEBUG, "unexpected: kevent() returned something != 0, -1 or 1");
			break;
		}
	}
}

static bool launchd_check_pid(pid_t p, int status)
{
	struct kevent kev;
	struct usercb *u;
	struct jobcb *j;

	TAILQ_FOREACH(u, &users, tqe) {
		TAILQ_FOREACH(j, &u->ujobs, tqe) {
			if (j->p == p) {
				EV_SET(&kev, p, EVFILT_PROC, 0, 0, 0, j);
				j->wstatus = status;
				j->kqjob_callback(j, &kev);
				return true;
			}
		}
	}
	return false;
}

static void launchd_remove_all_jobs(void)
{
	struct usercb *u;
	struct jobcb *j;

	TAILQ_FOREACH(u, &users, tqe) {
		while ((j = TAILQ_FIRST(&u->ujobs)))
			job_remove(j);
	}
}

static int launchd_server_init(char *thepath)
{
        struct sockaddr_un sun;
        char *where = getenv(LAUNCHD_SOCKET_ENV);
        mode_t oldmask;
        int fd;

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;

	if (thepath)
		thesockpath = thepath;
	else if (where)
		thesockpath = where;
	else
		thesockpath = LAUNCHD_DEFAULT_SOCK_PATH;
        strncpy(sun.sun_path, thesockpath, sizeof(sun.sun_path));


        if (unlink(sun.sun_path) == -1 && errno != ENOENT)
                return -1;
        if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	oldmask = umask(getpid() == 1 ? 0 : 077);
        if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
                close(fd);
		umask(oldmask);
		return -1;
        }
	umask(oldmask);
        if (listen(fd, SOMAXCONN) == -1) {
                close(fd);
		return -1;
        }

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
	kevent_mod(fd, EVFILT_READ, EV_ADD, 0, 0, &c->kqconn_callback);
}

static void simple_zombie_reaper(void *obj __attribute__((unused)), struct kevent *kev)
{
	waitpid(kev->ident, NULL, 0);
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
				syslog(LOG_DEBUG, "%s(): read: %m", __func__);
			ipc_close(c);
		}
	} else if (kev->filter == EVFILT_WRITE) {
		r = launchd_msg_send(c->conn, NULL);
		if (r == -1) {
			if (errno != EAGAIN) {
				syslog(LOG_DEBUG, "%s(): send: %m", __func__);
				ipc_close(c);
			}
		} else if (r == 0) {
			kevent_mod(launchd_getfd(c->conn), EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		}
	} else {
		syslog(LOG_DEBUG, "%s(): unknown filter type!", __func__);
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
		kevent_mod(launch_data_get_fd(o), EVFILT_READ, EV_DELETE, 0, 0, cookie);
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
		kevent_mod(launch_data_get_fd(o), EVFILT_READ, EV_ADD, 0, 0, cookie);
		break;
	default:
		break;
	}
}

static void job_remove(struct jobcb *j)
{
	TAILQ_REMOVE(find_jobq(job_get_integer(j->ldj, LAUNCH_JOBKEY_UID)), j, tqe);
        if (j->p) {
        	if (kevent_mod(j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) == -1) {
        		job_reap(j);
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
			kevent_mod(launchd_getfd(c->conn), EVFILT_WRITE, EV_ADD, 0, 0, &c->kqconn_callback);
		} else {
			syslog(LOG_DEBUG, "launchd_msg_send() == -1: %m");
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
	j->kqjob_callback = job_callback;

	if (c->u != 0) {
		tmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmp, c->u);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_UID);

		tmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmp, c->g);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_GID);

		launch_data_dict_remove(j->ldj, LAUNCH_JOBKEY_ROOTDIRECTORY);
	}
	
	if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_ONDEMAND) == NULL) {
		tmp = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(tmp, true);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_ONDEMAND);
	}

	if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_SERVICEIPC) == NULL) {
		tmp = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(tmp, true);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_SERVICEIPC);
	}

	if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_UMASK) == NULL) {
		tmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(tmp, ourmask);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_UMASK);
	}

	TAILQ_INSERT_TAIL(find_jobq(c->u), j, tqe);

	if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
		job_watch_fds(j->ldj, &j->kqjob_callback);
	else
		job_launch(j);

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

static void usage(FILE *where)
{
	fprintf(where, "%s:\n", getprogname());
	fprintf(where, "\t-d\tdebug mode\n");
	fprintf(where, "\t-S sock\talternate socket to use\n");
	fprintf(where, "\t-h\tthis usage statement\n");

	if (where == stdout)
		exit(EXIT_SUCCESS);
}

static void **machcbtable = NULL;
static size_t machcbtable_cnt = 0;
static int machcbreadfd = -1;
static int machcbwritefd = -1;
static mach_port_t mach_demand_port_set = MACH_PORT_NULL;
static pthread_t waitpid_demand_thread;
static pthread_t mach_demand_thread;

static void mach_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	struct kevent mkev;
	mach_port_t mp;

	read(machcbreadfd, &mp, sizeof(mp));

	EV_SET(&mkev, mp, EVFILT_MACHPORT, 0, 0, 0, machcbtable[MACH_PORT_INDEX(mp)]);

	(*((kq_callback *)mkev.udata))(mkev.udata, &mkev);
}

static int proccbreadfd = -1;
static int proccbwritefd = -1;
typedef struct {
	pid_t p;
	int status;
} wait_pass_results_t;

static void proc_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	wait_pass_results_t wpr;

	if (read(proccbreadfd, &wpr, sizeof(wpr)) == -1) {
		syslog(LOG_ERR, "read(wpr): %m");
		return;
	}

	if (!launchd_check_pid(wpr.p, wpr.status))
		init_check_pid(wpr.p, wpr.status);
}

static kq_callback kqproc_callback = proc_callback;

static void *waitpid_demand_loop(void *arg __attribute__((unused)))
{
	wait_pass_results_t wpr;

	for (;;) {
		wpr.p = waitpid(-1, &wpr.status, 0);
		if (wpr.p == -1) {
			syslog(LOG_DEBUG, "waitpid(): %m");
			continue;
		}
		if (write(proccbwritefd, &wpr, sizeof(wpr)) == -1)
			syslog(LOG_DEBUG, "write(wpr): %m");
	}
}

int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	kern_return_t kr;
	pthread_attr_t attr;
	int pthr_r, pfds[2];

	if (filter == EVFILT_PROC && getpid() == 1) {
		if (proccbreadfd > 0)
			return 0;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

		pthr_r = pthread_create(&waitpid_demand_thread, &attr, waitpid_demand_loop, NULL);
		if (pthr_r != 0) {
			syslog(LOG_ERR, "pthread_create(waitpid_demand_loop): %s", strerror(pthr_r));
			exit(EXIT_FAILURE);
		}

		pthread_attr_destroy(&attr);

		pipe(pfds);

		proccbwritefd = _fd(pfds[1]);
		proccbreadfd = _fd(pfds[0]);

		kevent_mod(proccbreadfd, EVFILT_READ, EV_ADD, 0, 0, &kqproc_callback);

		return 0;
	} else if (filter != EVFILT_MACHPORT) {
		EV_SET(&kev, ident, filter, flags, fflags, data, udata);
		return kevent(mainkq, &kev, 1, NULL, 0, NULL);
	}

	if (machcbtable == NULL) {
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

		pthr_r = pthread_create(&mach_demand_thread, &attr, mach_demand_loop, NULL);
		if (pthr_r != 0) {
			syslog(LOG_ERR, "pthread_create(mach_demand_loop): %s", strerror(pthr_r));
			exit(EXIT_FAILURE);
		}

		pthread_attr_destroy(&attr);

		machcbtable = malloc(0);
		pipe(pfds);
		machcbwritefd = _fd(pfds[1]);
		machcbreadfd = _fd(pfds[0]);
		kevent_mod(machcbreadfd, EVFILT_READ, EV_ADD, 0, 0, &kqmach_callback);
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &mach_demand_port_set);
		if (kr != KERN_SUCCESS) {
			syslog(LOG_ERR, "mach_port_allocate(demand_port_set): %s", mach_error_string(kr));
			exit(EXIT_FAILURE);
		}
	}

	if (flags & EV_ADD) {
		kr = mach_port_move_member(mach_task_self(), ident, mach_demand_port_set);
		if (kr != KERN_SUCCESS) {
			syslog(LOG_ERR, "mach_port_move_member(): %s", mach_error_string(kr));
			exit(EXIT_FAILURE);
		}

		if (MACH_PORT_INDEX(ident) > machcbtable_cnt)
			machcbtable = realloc(machcbtable, MACH_PORT_INDEX(ident) * sizeof(void *));

		machcbtable[MACH_PORT_INDEX(ident)] = udata;
	} else if (flags & EV_DELETE) {
		kr = mach_port_move_member(mach_task_self(), ident, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			syslog(LOG_ERR, "mach_port_move_member(): %s", mach_error_string(kr));
			exit(EXIT_FAILURE);
		}
	} else {
		syslog(LOG_DEBUG, "kevent_mod(EVFILT_MACHPORT) with flags: %d", flags);
		errno = EINVAL;
		return -1;
	}

	return 0;
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

static void job_reap(struct jobcb *j)
{
	if (j->wstatus == 0)
		waitpid(j->p, &j->wstatus, 0);

	if (WIFEXITED(j->wstatus)) {
		if (WEXITSTATUS(j->wstatus) > 0)
			syslog(LOG_WARNING, "%s[%d] exited with exit code %d",
					job_get_argv0(j->ldj), j->p, WEXITSTATUS(j->wstatus));
	} else if (WIFSIGNALED(j->wstatus)) {
		syslog(LOG_WARNING, "%s[%d] exited abnormally with signal %d",
					job_get_argv0(j->ldj), j->p, WTERMSIG(j->wstatus));
	}

	j->p = 0;
	j->wstatus = 0;
	j->checkedin = false;
}

static void job_callback(void *obj, struct kevent *kev)
{
	struct jobcb *j = obj;

	if (kev->filter == EVFILT_PROC) {

		if (job_get_bool(j->ldj, LAUNCH_JOBKEY_SERVICEIPC) && !j->checkedin) {
			syslog(LOG_WARNING, "%s failed to checkin, removing job", job_get_argv0(j->ldj));
			job_remove(j);
			return;
		}

		job_reap(j);

		if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND)) {
			job_watch_fds(j->ldj, &j->kqjob_callback);
			return;
		}
	}

	job_launch(j);
}

static void job_launch(struct jobcb *j)
{
	char nbuf[64];
        pid_t c;
	int spair[2];
	const char **argv;
	bool sipc = job_get_bool(j->ldj, LAUNCH_JOBKEY_SERVICEIPC);

	if (sipc)
		socketpair(AF_UNIX, SOCK_STREAM, 0, spair);

        if ((c = fork_with_bootstrap_port(launchd_bootstrap_port)) == -1) {
                syslog(LOG_WARNING, "fork(): %m");
                return;
        } else if (c == 0) {
		launch_data_t ldpa = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
		size_t i, argv_cnt;
		char *a0;

		argv_cnt = launch_data_array_get_count(ldpa);
		argv = alloca((argv_cnt + 1) * sizeof(char *));
		for (i = 0; i < argv_cnt; i++)
			argv[i] = launch_data_get_string(launch_data_array_get_index(ldpa, i));
		argv[argv_cnt] = NULL;

		if (sipc)
			close(spair[0]);
		if (job_get_string(j->ldj, LAUNCH_JOBKEY_ROOTDIRECTORY))
			chroot(job_get_string(j->ldj, LAUNCH_JOBKEY_ROOTDIRECTORY));
		if (job_get_integer(j->ldj, LAUNCH_JOBKEY_GID) != getegid())
			setgid(job_get_integer(j->ldj, LAUNCH_JOBKEY_GID));
		if (job_get_integer(j->ldj, LAUNCH_JOBKEY_UID) != geteuid())
			setuid(job_get_integer(j->ldj, LAUNCH_JOBKEY_UID));
		if (job_get_string(j->ldj, LAUNCH_JOBKEY_WORKINGDIRECTORY))
			chdir(job_get_string(j->ldj, LAUNCH_JOBKEY_WORKINGDIRECTORY));
		if (job_get_integer(j->ldj, LAUNCH_JOBKEY_UMASK) != ourmask)
			umask(job_get_integer(j->ldj, LAUNCH_JOBKEY_UMASK));
		if (job_get_string(j->ldj, LAUNCH_JOBKEY_STANDARDOUTPATH)) {
			int sofd = open(job_get_string(j->ldj, LAUNCH_JOBKEY_STANDARDOUTPATH), O_WRONLY|O_APPEND|O_CREAT, 0666);
			dup2(sofd, STDOUT_FILENO);
			close(sofd);
		}
		if (job_get_string(j->ldj, LAUNCH_JOBKEY_STANDARDERRORPATH)) {
			int sefd = open(job_get_string(j->ldj, LAUNCH_JOBKEY_STANDARDERRORPATH), O_WRONLY|O_APPEND|O_CREAT, 0666);
			dup2(sefd, STDERR_FILENO);
			close(sefd);
		}
		if (sipc)
			sprintf(nbuf, "%d", spair[1]);
#ifdef FIXME
		launch_data_dict_iterate(j->uenv, setup_job_env, NULL);
#endif
		if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES))
			launch_data_dict_iterate(launch_data_dict_lookup(j->ldj,
						LAUNCH_JOBKEY_ENVIRONMENTVARIABLES),
					setup_job_env, NULL);
		if (sipc)
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
                setsid();
		setpriority(PRIO_PROCESS, 0, 0);
		if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_INETDCOMPATIBILITY))
			a0 = "/usr/libexec/launchproxy";
		else
			a0 = job_get_argv0(j->ldj);
                if (execvp(a0, (char *const*)argv) == -1)
			syslog(LOG_ERR, "child execvp(): %m");
                exit(EXIT_FAILURE);
        }

	if (sipc) {
		close(spair[1]);
		ipc_open(_fd(spair[0]), j);
	}

        if (kevent_mod(c, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &j->kqjob_callback) == -1) {
                syslog(LOG_WARNING, "kevent(): %m");
                return;
        } else {
	        j->p = c;
		if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
			job_ignore_fds(j->ldj, j->kqjob_callback);
	}
}

static void signal_callback(void *obj __attribute__((unused)), struct kevent *kev)
{
	switch (kev->ident) {
	case SIGHUP:
		update_ttys();
		break;
	case SIGTERM:
		launchd_remove_all_jobs();
		catatonia();
		mach_start_shutdown(SIGTERM);
		break;
	case SIGUSR1:
		debug = !debug;
		update_lm();
		break;
	case SIGUSR2:
		verbose = !verbose;
		update_lm();
		break;
	default:
		break;
	}
}

static void update_lm(void)
{
	int oldlm, lm = LOG_UPTO(LOG_NOTICE);
	const char *lstr = "verbose";
	const char *e_vs_d = "disabled";
	if (verbose) {
		lm = LOG_UPTO(LOG_INFO);
		e_vs_d = "enabled";
	}
	if (debug) {
		lm = LOG_UPTO(LOG_DEBUG);
		lstr = "debug";
		e_vs_d = "enabled";
	}
	oldlm = setlogmask(lm);
	if (lm != oldlm)
		syslog(LOG_NOTICE, "%s logging %s", lstr, e_vs_d);
}

static void fs_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	if (thesocket == -1) {
		if ((thesocket = _fd(launchd_server_init(thesockpath))) > 0) {
			if (kevent_mod(thesocket, EVFILT_READ, EV_ADD, 0, 0, &kqlisten_callback) == -1)
				syslog(LOG_ERR, "kevent_mod(\"thesocket\", EVFILT_READ): %m");
			setenv(LAUNCHD_SOCKET_ENV, thesockpath, 1);
		}
	}
}

static void dummysignalhandler(int sig __attribute__((unused)))
{
}


static void *mach_demand_loop(void *arg __attribute__((unused)))
{
	mach_msg_empty_rcv_t dummy;
	kern_return_t kr;
	mach_port_name_array_t members;
	mach_msg_type_number_t membersCnt;
	mach_port_status_t status;
	mach_msg_type_number_t statusCnt;
	unsigned int i;

	for (;;) {

		/*
		 * Receive indication of message on demand service
		 * ports without actually receiving the message (we'll
		 * let the actual server do that.
		 */
		kr = mach_msg(&dummy.header, MACH_RCV_MSG|MACH_RCV_LARGE,
				0, 0, mach_demand_port_set, 0, MACH_PORT_NULL);
		if (kr != MACH_RCV_TOO_LARGE) {
			syslog(LOG_WARNING, "%s(): mach_msg(): %s", __func__, mach_error_string(kr));
			continue;
		}

		/*
		 * Some port(s) now have messages on them, find out
		 * which ones (there is no indication of which port
		 * triggered in the MACH_RCV_TOO_LARGE indication).
		 */
		kr = mach_port_get_set_status(mach_task_self(),
				mach_demand_port_set, &members, &membersCnt);
		if (kr != KERN_SUCCESS) {
			syslog(LOG_WARNING, "%s(): mach_port_get_set_status(): %s", __func__, mach_error_string(kr));
			continue;
		}

		for (i = 0; i < membersCnt; i++) {
			statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
			kr = mach_port_get_attributes(mach_task_self(), members[i],
					MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &statusCnt);
			if (kr != KERN_SUCCESS) {
				syslog(LOG_WARNING, "%s(): mach_port_get_attributes(): %s", __func__, mach_error_string(kr));
				continue;
			}

			/*
			 * For each port with messages, take it out of the
			 * demand service portset, and inform the main thread
			 * that it might have to start the server responsible
			 * for it.
			 */
			if (status.mps_msgcount) {
				kr = mach_port_move_member(mach_task_self(), members[i], MACH_PORT_NULL);
				if (kr != KERN_SUCCESS) {
					syslog(LOG_WARNING, "%s(): mach_port_move_member(): %s", __func__, mach_error_string(kr));
					continue;
				}
				write(machcbwritefd, &(members[i]), sizeof(members[i]));
			}
		}

		kr = vm_deallocate(mach_task_self(), (vm_address_t) members,
				(vm_size_t) membersCnt * sizeof(mach_port_name_t));
		if (kr != KERN_SUCCESS) {
			syslog(LOG_WARNING, "%s(): vm_deallocate(): %s", __func__, mach_error_string(kr));
			continue;
		}
	}

	return NULL;
}

static void loopback_setup(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
	struct ifaliasreq ifra;
	struct in6_aliasreq ifra6;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

        if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
                syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %m");
        } else {
        	ifr.ifr_flags |= IFF_UP;

        	if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1)
                	syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %m");
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

        if (ioctl(s6, SIOCGIFFLAGS, &ifr) == -1) {
                syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %m");
        } else {
        	ifr.ifr_flags |= IFF_UP;

        	if (ioctl(s6, SIOCSIFFLAGS, &ifr) == -1)
                	syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %m");
	}

	memset(&ifra, 0, sizeof(ifra));
	strcpy(ifra.ifra_name, "lo0");

	((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr = htonl(IN_CLASSA_NET);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_len = sizeof(struct sockaddr_in);

	if (ioctl(s, SIOCAIFADDR, &ifra) == -1)
		syslog(LOG_ERR, "ioctl(SIOCAIFADDR ipv4): %m");

	memset(&ifra6, 0, sizeof(ifra6));
	strcpy(ifra6.ifra_name, "lo0");

	ifra6.ifra_addr.sin6_family = AF_INET6;
	ifra6.ifra_addr.sin6_addr = in6addr_loopback;
	ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_prefixmask.sin6_family = AF_INET6;
	memset(&ifra6.ifra_prefixmask.sin6_addr, 0xff, sizeof(struct in6_addr));
	ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	if (ioctl(s6, SIOCAIFADDR_IN6, &ifra6) == -1)
		syslog(LOG_ERR, "ioctl(SIOCAIFADDR ipv6): %m");
 
	close(s);
	close(s6);
}

static void workaround3048875(int argc, char *argv[])
{
	size_t i;
	char **ap, *newargv[100], *p = argv[1];

	if (argc == 1 || argc > 2)
		return;

	newargv[0] = argv[0];
	for (ap = newargv + 1, i = 1; ap < &newargv[100]; ap++, i++) {
		if ((*ap = strsep(&p, " \t")) == NULL)
			break;
		if (**ap == '\0') {
			*ap = NULL;
			break;
		}
	}

	if (argc == i)
		return;

	execv(newargv[0], newargv);
}
