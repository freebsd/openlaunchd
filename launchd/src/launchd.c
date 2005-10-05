/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <Security/AuthSession.h>
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
#include <sys/mount.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <paths.h>
#include <pwd.h>
#include <grp.h>
#include <ttyent.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

#include "launch.h"
#include "launch_priv.h"
#include "launchd.h"

#define LAUNCHD_MIN_JOB_RUN_TIME 10
#define LAUNCHD_REWARD_JOB_RUN_TIME 60
#define LAUNCHD_FAILED_EXITS_THRESHOLD 10
#define PID1LAUNCHD_CONF "/etc/launchd.conf"
#define LAUNCHD_CONF ".launchd.conf"
#define LAUNCHCTL_PATH "/bin/launchctl"
#define SECURITY_LIB "/System/Library/Frameworks/Security.framework/Versions/A/Security"
#define VOLFSDIR "/.vol"

extern char **environ;

struct jobcb {
	kq_callback kqjob_callback;
	SLIST_ENTRY(jobcb) sle;
	launch_data_t ldj;
	pid_t p;
	int last_exit_status;
	int execfd;
	time_t start_time;
	size_t failed_exits;
	int *vnodes;
	size_t vnodes_cnt;
	int *qdirs;
	size_t qdirs_cnt;
	unsigned int start_interval;
	struct tm *start_cal_interval;
	unsigned int checkedin:1, firstborn:1, debug:1, throttle:1, futureflags:28;
	char label[0];
};

struct conncb {
	kq_callback kqconn_callback;
	SLIST_ENTRY(conncb) sle;
	launch_t conn;
	struct jobcb *j;
	int disabled_batch:1, futureflags:31;
};

static SLIST_HEAD(, jobcb) jobs = { NULL };
static SLIST_HEAD(, conncb) connections = { NULL };
static int mainkq = 0;
static int asynckq = 0;
static int batch_disabler_count = 0;

static launch_data_t setstdio(int d, launch_data_t o);
static launch_data_t adjust_rlimits(launch_data_t in);
static void batch_job_enable(bool e, struct conncb *c);
static void launchd_shutdown(void);
static void launchd_single_user(void);

static void listen_callback(void *, struct kevent *);
static void async_callback(void);
static void signal_callback(void *, struct kevent *);
static void fs_callback(void);
static void simple_zombie_reaper(void *, struct kevent *);
static void readcfg_callback(void *, struct kevent *);

static kq_callback kqlisten_callback = listen_callback;
static kq_callback kqasync_callback = (kq_callback)async_callback;
static kq_callback kqsignal_callback = signal_callback;
static kq_callback kqfs_callback = (kq_callback)fs_callback;
static kq_callback kqreadcfg_callback = readcfg_callback;
static kq_callback kqshutdown_callback = (kq_callback)launchd_shutdown;
kq_callback kqsimple_zombie_reaper = simple_zombie_reaper;

static struct jobcb *job_find(const char *label);
static struct jobcb *job_import(launch_data_t pload);
static launch_data_t job_export(struct jobcb *j);
static launch_data_t job_export_all(void);
static void job_watch(struct jobcb *j);
static void job_ignore(struct jobcb *j);
static void job_start(struct jobcb *j);
static void job_start_child(struct jobcb *j, int execfd) __attribute__((noreturn));
static void job_setup_attributes(struct jobcb *j);
static void job_stop(struct jobcb *j);
static void job_reap(struct jobcb *j);
static void job_remove(struct jobcb *j);
static void job_set_alarm(struct jobcb *j);
static void job_callback(void *obj, struct kevent *kev);
static void job_log(struct jobcb *j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
static void job_log_error(struct jobcb *j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));

static void ipc_open(int fd, struct jobcb *j);
static void ipc_close(struct conncb *c);
static void ipc_callback(void *, struct kevent *);
static void ipc_readmsg(launch_data_t msg, void *context);
static void ipc_readmsg2(launch_data_t data, const char *cmd, void *context);

#ifdef PID1_REAP_ADOPTED_CHILDREN
static void pid1waitpid(void);
static bool launchd_check_pid(pid_t p);
#endif
static void pid1_magic_init(bool sflag, bool vflag, bool xflag);
static void launchd_server_init(void);
static struct jobcb *conceive_firstborn(char *argv[], const char *session_user);

static void usage(FILE *where);
static int _fd(int fd);

static void loopback_setup(void);
static void workaround3048875(int argc, char *argv[]);
static void testfd_or_openfd(int fd, const char *path, int flags);
static void reload_launchd_config(void);
static int dir_has_files(const char *path);
static void testfd_or_openfd(int fd, const char *path, int flags);
static void setup_job_env(launch_data_t obj, const char *key, void *context);
static void unsetup_job_env(launch_data_t obj, const char *key, void *context);


static size_t total_children = 0;
static pid_t readcfg_pid = 0;
static pid_t launchd_proper_pid = 0;
static bool launchd_inited = false;
static bool shutdown_in_progress = false;
static bool re_exec_in_single_user_mode = false;
sigset_t blocked_signals = 0;
static char *pending_stdout = NULL;
static char *pending_stderr = NULL;
static struct jobcb *fbj = NULL;

int main(int argc, char *argv[])
{
	static const int sigigns[] = { SIGHUP, SIGINT, SIGPIPE, SIGALRM,
		SIGTERM, SIGURG, SIGTSTP, SIGTSTP, SIGCONT, /*SIGCHLD,*/
		SIGTTIN, SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2
	};
	bool sflag = false, xflag = false, vflag = false, dflag = false;
	const char *session_type = NULL;
	const char *session_user = NULL;
	const char *optargs = NULL;
	struct kevent kev;
	size_t i;
	int ch, ker;

	/* main() phase one: sanitize the process */

	if (getpid() == 1) {
		workaround3048875(argc, argv);
	} else {
		int sigi, fdi, dts = getdtablesize();
		sigset_t emptyset;

		for (fdi = STDERR_FILENO + 1; fdi < dts; fdi++)
			launchd_assumes(close(fdi) == 0);
		for (sigi = 1; sigi < NSIG; sigi++)
			launchd_assumes(signal(sigi, SIG_DFL) != SIG_ERR);
		sigemptyset(&emptyset);
		launchd_assumes(sigprocmask(SIG_SETMASK, &emptyset, NULL) == 0);
	}

	testfd_or_openfd(STDIN_FILENO, _PATH_DEVNULL, O_RDONLY);
	testfd_or_openfd(STDOUT_FILENO, _PATH_DEVNULL, O_WRONLY);
	testfd_or_openfd(STDERR_FILENO, _PATH_DEVNULL, O_WRONLY);

	/* main phase two: parse arguments */

	if (getpid() == 1) {
		optargs = "svx";
	} else if (getuid() == 0) {
		optargs = "S:U:dh";
	} else {
		optargs = "dh";
	}

	while ((ch = getopt(argc, argv, optargs)) != -1) {
		switch (ch) {
		case 'S': session_type = optarg; break;	/* what type of session we're creating */
		case 'U': session_user = optarg; break;	/* which user to create a session as */
		case 'd': dflag = true;   break;	/* daemonize */
		case 's': sflag = true;   break;	/* single user */
		case 'x': xflag = true;   break;	/* safe boot */
		case 'v': vflag = true;   break;	/* verbose boot */
		case 'h': usage(stdout);  break;	/* help */
		case '?': /* we should do something with the global optopt variable here */
		default:
			fprintf(stderr, "ignoring unknown arguments\n");
			usage(stderr);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if ((session_type && !session_user) || (!session_user && session_type)) {
		fprintf(stderr, "-S and -U must be used together\n");
		exit(EXIT_FAILURE);
	}

	/* main phase three: if we need to become a user, do so ASAP */
	
	if (session_user) {
		struct passwd *pwe = getpwnam(session_user);
		uid_t u = pwe ? pwe->pw_uid : 0;
		gid_t g = pwe ? pwe->pw_gid : 0;
		
		if (pwe == NULL) {
			fprintf(stderr, "lookup of user %s failed!\n", session_user);
			exit(EXIT_FAILURE);
		}

		launchd_assert(initgroups(session_user, g) != -1);

		launchd_assert(setgid(g) != -1);

		launchd_assert(setuid(u) != -1);
	}

	/* main phase four: get the party started */

	if (dflag)
		launchd_assumes(daemon(0, 0) == 0);

	openlog(getprogname(), LOG_CONS|(getpid() != 1 ? LOG_PID|LOG_PERROR : 0), LOG_LAUNCHD);
	setlogmask(LOG_UPTO(LOG_NOTICE));

	launchd_assert((mainkq = kqueue()) != -1);

	launchd_assert((asynckq = kqueue()) != -1);
	
	launchd_assert(kevent_mod(asynckq, EVFILT_READ, EV_ADD, 0, 0, &kqasync_callback) != -1);

	sigemptyset(&blocked_signals);

	for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
		launchd_assumes(kevent_mod(sigigns[i], EVFILT_SIGNAL, EV_ADD, 0, 0, &kqsignal_callback) != -1);
		sigaddset(&blocked_signals, sigigns[i]);
		launchd_assumes(signal(sigigns[i], SIG_IGN) != SIG_ERR);
	}

	/* sigh... ignoring SIGCHLD has side effects: we can't call wait*() */
	launchd_assert(kevent_mod(SIGCHLD, EVFILT_SIGNAL, EV_ADD, 0, 0, &kqsignal_callback) != -1);

	if (argv[0] || (session_type != NULL && 0 == strcasecmp(session_type, "tty")))
		fbj = conceive_firstborn(argv, session_user);
	
	mach_init_init();

	if (NULL == getenv("PATH"))
		setenv("PATH", _PATH_STDPATH, 1);

	if (getpid() == 1) {
		pid1_magic_init(sflag, vflag, xflag);
	} else {
		launchd_server_init();
	}

	/* do this after pid1_magic_init() to not catch ourselves mounting stuff */
	launchd_assumes(kevent_mod(0, EVFILT_FS, EV_ADD, 0, 0, &kqfs_callback) != -1);

	if (session_type) {
		pid_t pp = getppid();

		/* As a per session launchd, we need to exit if our parent dies.
		 *
		 * Normally, in Unix, SIGHUP would cause us to exit, but we're a
		 * daemon, and daemons use SIGHUP to signal the need to reread
		 * configuration files. "Weee."
		 */

		if (pp == 1)
			exit(EXIT_SUCCESS);

		ker = kevent_mod(pp, EVFILT_PROC, EV_ADD, 0, 0, &kqshutdown_callback);

		if (ker == -1)
			exit(launchd_assumes(errno == ESRCH) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	reload_launchd_config();

	if (fbj && fbj->firstborn)
		job_start(fbj);

	for (;;) {
		if (getpid() == 1 && readcfg_pid == 0)
			init_pre_kevent();

		if (shutdown_in_progress && total_children == 0) {
			struct jobcb *j;

			while ((j = SLIST_FIRST(&jobs)))
				job_remove(j);
			
			shutdown_in_progress = false;

			mach_init_reap();

			if (getpid() != 1) {
				exit(EXIT_SUCCESS);
			} else if (re_exec_in_single_user_mode) {
				re_exec_in_single_user_mode = false;
				launchd_assumes(execl("/sbin/launchd", "/sbin/launchd", "-s", NULL) != -1);
			}
		}

		if (launchd_assumes(kevent(mainkq, NULL, 0, &kev, 1, NULL) == 1))
			(*((kq_callback *)kev.udata))(kev.udata, &kev);
	}
}

static void pid1_magic_init(bool sflag, bool vflag, bool xflag)
{
	int memmib[2] = { CTL_HW, HW_PHYSMEM };
	int mvnmib[2] = { CTL_KERN, KERN_MAXVNODES };
	int hnmib[2] = { CTL_KERN, KERN_HOSTNAME };
	uint64_t mem = 0;
	uint32_t mvn;
	size_t memsz = sizeof(mem);
		
	setpriority(PRIO_PROCESS, 0, -1);

	if (setsid() == -1)
		syslog(LOG_ERR, "setsid(): %m");

	if (chdir("/") == -1)
		syslog(LOG_ERR, "chdir(\"/\"): %m");

	if (sysctl(memmib, 2, &mem, &memsz, NULL, 0) == -1) {
		syslog(LOG_WARNING, "sysctl(\"%s\"): %m", "hw.physmem");
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
			syslog(LOG_WARNING, "sysctl(\"%s\"): %m", "kern.maxvnodes");
	}
	if (sysctl(hnmib, 2, NULL, NULL, "localhost", sizeof("localhost")) == -1)
		syslog(LOG_WARNING, "sysctl(\"%s\"): %m", "kern.hostname");

	if (setlogin("root") == -1)
		syslog(LOG_ERR, "setlogin(\"root\"): %m");

	loopback_setup();

	if (mount("fdesc", "/dev", MNT_UNION, NULL) == -1)
		syslog(LOG_ERR, "mount(\"%s\", \"%s\", ...): %m", "fdesc", "/dev/");

	init_boot(sflag, vflag, xflag);
}


#ifdef PID1_REAP_ADOPTED_CHILDREN
static bool launchd_check_pid(pid_t p)
{
	struct kevent kev;
	struct jobcb *j;

	SLIST_FOREACH(j, &jobs, sle) {
		if (j->p == p) {
			EV_SET(&kev, p, EVFILT_PROC, 0, 0, 0, j);
			j->kqjob_callback(j, &kev);
			return true;
		}
	}

	if (p == readcfg_pid) {
		readcfg_callback(NULL, NULL);
		return true;
	}

	return false;
}
#endif

static char *sockdir = NULL;
static char *sockpath = NULL;

static void launchd_clean_up(void)
{
	if (launchd_proper_pid != getpid())
		return;

	if (-1 == unlink(sockpath))
		syslog(LOG_WARNING, "unlink(\"%s\"): %m", sockpath);
	else if (-1 == rmdir(sockdir))
		syslog(LOG_WARNING, "rmdir(\"%s\"): %m", sockdir);
}

static void launchd_server_init(void)
{
	struct sockaddr_un sun;
	mode_t oldmask;
	int r, fd = -1;
	char ourdir[1024];

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	if (getpid() == 1) {
		strcpy(ourdir, LAUNCHD_SOCK_PREFIX);
		strncpy(sun.sun_path, LAUNCHD_SOCK_PREFIX "/sock", sizeof(sun.sun_path));

		unlink(ourdir);
		if (mkdir(ourdir, S_IRWXU) == -1) {
			if (errno == EROFS) {
				goto out_bad;
			} else if (errno == EEXIST) {
				struct stat sb;
				stat(ourdir, &sb);
				if (!S_ISDIR(sb.st_mode)) {
					errno = EEXIST;
					syslog(LOG_ERR, "mkdir(\"%s\"): %m", LAUNCHD_SOCK_PREFIX);
					goto out_bad;
				}
			} else {
				syslog(LOG_ERR, "mkdir(\"%s\"): %m", ourdir);
				goto out_bad;
			}
		}
	} else {
		snprintf(ourdir, sizeof(ourdir), "/tmp/launchd-%u.XXXXXX", getpid());
		mkdtemp(ourdir);
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/sock", ourdir);
		setenv(LAUNCHD_SOCKET_ENV, sun.sun_path, 1);
	}

	if (unlink(sun.sun_path) == -1 && errno != ENOENT) {
		if (errno != EROFS)
			syslog(LOG_ERR, "unlink(\"thesocket\"): %m");
		goto out_bad;
	}
	if ((fd = _fd(socket(AF_UNIX, SOCK_STREAM, 0))) == -1) {
		syslog(LOG_ERR, "socket(\"thesocket\"): %m");
		goto out_bad;
	}

	oldmask = umask(S_IRWXG|S_IRWXO);
	r = bind(fd, (struct sockaddr *)&sun, sizeof(sun));
	umask(oldmask);

	if (r == -1) {
		if (errno != EROFS)
			syslog(LOG_ERR, "bind(\"thesocket\"): %m");
		goto out_bad;
	}

	if (listen(fd, SOMAXCONN) == -1) {
		syslog(LOG_ERR, "listen(\"thesocket\"): %m");
		goto out_bad;
	}

	if (kevent_mod(fd, EVFILT_READ, EV_ADD, 0, 0, &kqlisten_callback) == -1) {
		syslog(LOG_ERR, "kevent_mod(\"thesocket\", EVFILT_READ): %m");
		goto out_bad;
	}

	launchd_inited = true;

	sockdir = strdup(ourdir);
	sockpath = strdup(sun.sun_path);

	launchd_proper_pid = getpid();
	atexit(launchd_clean_up);

out_bad:
	if (!launchd_inited && fd != -1)
		launchd_assumes(close(fd) == 0);
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

static const char *job_get_file2exec(launch_data_t j)
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
	struct conncb *c = calloc(1, sizeof(struct conncb));

	fcntl(fd, F_SETFL, O_NONBLOCK);

	c->kqconn_callback = ipc_callback;
	c->conn = launchd_fdopen(fd);
	c->j = j;
	SLIST_INSERT_HEAD(&connections, c, sle);
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
				syslog(LOG_DEBUG, "%s(): recv: %m", __func__);
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

static void set_user_env(launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	setenv(key, launch_data_get_string(obj), 1);
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
		if (launch_data_get_fd(o) != -1)
			launchd_assumes(close(launch_data_get_fd(o)) == 0);
		break;
	default:
		break;
	}
}

static void launch_data_revoke_fds(launch_data_t o)
{
	size_t i;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, (void (*)(launch_data_t, const char *, void *))launch_data_revoke_fds, NULL);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			launch_data_revoke_fds(launch_data_array_get_index(o, i));
		break;
	case LAUNCH_DATA_FD:
		launch_data_set_fd(o, -1);
		break;
	default:
		break;
	}
}

static void job_ignore_fds(launch_data_t o, const char *key __attribute__((unused)), void *cookie)
{
	struct jobcb *j = cookie;
	size_t i;
	int fd;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, job_ignore_fds, cookie);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			job_ignore_fds(launch_data_array_get_index(o, i), NULL, cookie);
		break;
	case LAUNCH_DATA_FD:
		fd = launch_data_get_fd(o);
		if (-1 != fd) {
			job_log(j, LOG_DEBUG, "Ignoring FD: %d", fd);
			kevent_mod(fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		}
		break;
	default:
		break;
	}
}

static void job_ignore(struct jobcb *j)
{
	launch_data_t j_sockets = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_SOCKETS);
	size_t i;

	if (j_sockets)
		job_ignore_fds(j_sockets, NULL, j);

	for (i = 0; i < j->vnodes_cnt; i++) {
		kevent_mod(j->vnodes[i], EVFILT_VNODE, EV_DELETE, 0, 0, NULL);
	}
	for (i = 0; i < j->qdirs_cnt; i++) {
		kevent_mod(j->qdirs[i], EVFILT_VNODE, EV_DELETE, 0, 0, NULL);
	}
}

static void job_watch_fds(launch_data_t o, const char *key __attribute__((unused)), void *cookie)
{
	struct jobcb *j = cookie;
	size_t i;
	int fd;

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, job_watch_fds, cookie);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			job_watch_fds(launch_data_array_get_index(o, i), NULL, cookie);
		break;
	case LAUNCH_DATA_FD:
		fd = launch_data_get_fd(o);
		if (-1 != fd) {
			job_log(j, LOG_DEBUG, "Watching FD: %d", fd);
			kevent_mod(fd, EVFILT_READ, EV_ADD, 0, 0, cookie);
		}
		break;
	default:
		break;
	}
}

static void job_watch(struct jobcb *j)
{
	launch_data_t ld_qdirs = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_QUEUEDIRECTORIES);
	launch_data_t ld_vnodes = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_WATCHPATHS);
	launch_data_t j_sockets = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_SOCKETS);
	size_t i;

	if (j_sockets)
		job_watch_fds(j_sockets, NULL, &j->kqjob_callback);

	for (i = 0; i < j->vnodes_cnt; i++) {
		if (-1 == j->vnodes[i]) {
			launch_data_t ld_idx = launch_data_array_get_index(ld_vnodes, i);
			const char *thepath = launch_data_get_string(ld_idx);

			if (-1 == (j->vnodes[i] = _fd(open(thepath, O_EVTONLY))))
				job_log_error(j, LOG_ERR, "open(\"%s\", O_EVTONLY)", thepath);
		}
		kevent_mod(j->vnodes[i], EVFILT_VNODE, EV_ADD|EV_CLEAR,
				NOTE_WRITE|NOTE_EXTEND|NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE|NOTE_ATTRIB|NOTE_LINK,
				0, &j->kqjob_callback);
	}

	for (i = 0; i < j->qdirs_cnt; i++) {
		kevent_mod(j->qdirs[i], EVFILT_VNODE, EV_ADD|EV_CLEAR,
				NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_LINK, 0, &j->kqjob_callback);
	}

	for (i = 0; i < j->qdirs_cnt; i++) {
		launch_data_t ld_idx = launch_data_array_get_index(ld_qdirs, i);
		const char *thepath = launch_data_get_string(ld_idx);
		int dcc_r;

		if (-1 == (dcc_r = dir_has_files(thepath))) {
			job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", thepath);
		} else if (dcc_r > 0 && !shutdown_in_progress) {
			job_start(j);
			break;
		}
	}
}

static void job_stop(struct jobcb *j)
{
	if (j->p)
		kill(j->p, SIGTERM);
}

static launch_data_t job_export(struct jobcb *j)
{
	launch_data_t tmp, r = launch_data_copy(j->ldj);

	if (r) {
		tmp = launch_data_new_integer(j->last_exit_status);
		if (tmp)
			launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LASTEXITSTATUS);

		if (j->p) {
			tmp = launch_data_new_integer(j->p);
			if (tmp)
				launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PID);
		}
	}

	return r;
}

static void job_remove(struct jobcb *j)
{
	launch_data_t tmp;
	size_t i;

	job_log(j, LOG_DEBUG, "Removed");

	SLIST_REMOVE(&jobs, j, jobcb, sle);
	if (j->p) {
		if (kevent_mod(j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) == -1) {
			job_reap(j);
		} else {
			job_stop(j);
		}
	}
	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES)))
		launch_data_dict_iterate(tmp, unsetup_job_env, NULL);
	launch_data_close_fds(j->ldj);
	launch_data_free(j->ldj);
	if (j->execfd)
		launchd_assumes(close(j->execfd) == 0);
	for (i = 0; i < j->vnodes_cnt; i++)
		if (-1 != j->vnodes[i])
			launchd_assumes(close(j->vnodes[i]) == 0);
	if (j->vnodes)
		free(j->vnodes);
	for (i = 0; i < j->qdirs_cnt; i++)
		if (-1 != j->qdirs[i])
			launchd_assumes(close(j->qdirs[i]) == 0);
	if (j->qdirs)
		free(j->qdirs);
	if (j->start_interval)
		kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	if (j->start_cal_interval) {
		kevent_mod((uintptr_t)j->start_cal_interval, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
		free(j->start_cal_interval);
	}
	kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	free(j);
}

struct readmsg_context {
	struct conncb *c;
	launch_data_t resp;
};

static void ipc_readmsg(launch_data_t msg, void *context)
{
	struct readmsg_context rmc = { context, NULL };

	if (LAUNCH_DATA_DICTIONARY == launch_data_get_type(msg)) {
		launch_data_dict_iterate(msg, ipc_readmsg2, &rmc);
	} else if (LAUNCH_DATA_STRING == launch_data_get_type(msg)) {
		ipc_readmsg2(NULL, launch_data_get_string(msg), &rmc);
	} else {
		rmc.resp = launch_data_new_errno(EINVAL);
	}

	if (NULL == rmc.resp)
		rmc.resp = launch_data_new_errno(ENOSYS);

	launch_data_close_fds(msg);

	if (launchd_msg_send(rmc.c->conn, rmc.resp) == -1) {
		if (errno == EAGAIN) {
			kevent_mod(launchd_getfd(rmc.c->conn), EVFILT_WRITE, EV_ADD, 0, 0, &rmc.c->kqconn_callback);
		} else {
			syslog(LOG_DEBUG, "launchd_msg_send() == -1: %m");
			ipc_close(rmc.c);
		}
	}
	launch_data_free(rmc.resp);
}


static void ipc_readmsg2(launch_data_t data, const char *cmd, void *context)
{
	struct readmsg_context *rmc = context;
	launch_data_t resp = NULL;
	struct jobcb *j;

	if (rmc->resp)
		return;

	if (!strcmp(cmd, LAUNCH_KEY_STARTJOB)) {
		if ((j = job_find(launch_data_get_string(data))) != NULL) {
			job_start(j);
			errno = 0;
		}
		resp = launch_data_new_errno(errno);
	} else if (!strcmp(cmd, LAUNCH_KEY_STOPJOB)) {
		if ((j = job_find(launch_data_get_string(data))) != NULL) {
			job_stop(j);
			errno = 0;
		}
		resp = launch_data_new_errno(errno);
	} else if (!strcmp(cmd, LAUNCH_KEY_REMOVEJOB)) {
		if ((j = job_find(launch_data_get_string(data))) != NULL) {
			job_remove(j);
			errno = 0;
		}
		resp = launch_data_new_errno(errno);
	} else if (!strcmp(cmd, LAUNCH_KEY_SUBMITJOB)) {
		if (launch_data_get_type(data) == LAUNCH_DATA_ARRAY) {
			size_t i;

			resp = launch_data_alloc(LAUNCH_DATA_ARRAY);
			for (i = 0; i < launch_data_array_get_count(data); i++) {
				if (job_import(launch_data_array_get_index(data, i)))
					errno = 0;
				launch_data_array_set_index(resp, launch_data_new_errno(errno), i);
			}
		} else {
			if (job_import(data))
				errno = 0;
			resp = launch_data_new_errno(errno);
		}
	} else if (!strcmp(cmd, LAUNCH_KEY_UNSETUSERENVIRONMENT)) {
		unsetenv(launch_data_get_string(data));
		resp = launch_data_new_errno(0);
	} else if (!strcmp(cmd, LAUNCH_KEY_GETUSERENVIRONMENT)) {
		char **tmpenviron = environ;
		resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		for (; *tmpenviron; tmpenviron++) {
			char envkey[1024];
			launch_data_t s = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(s, strchr(*tmpenviron, '=') + 1);
			strncpy(envkey, *tmpenviron, sizeof(envkey));
			*(strchr(envkey, '=')) = '\0';
			launch_data_dict_insert(resp, s, envkey);
		}
	} else if (!strcmp(cmd, LAUNCH_KEY_SETUSERENVIRONMENT)) {
		launch_data_dict_iterate(data, set_user_env, NULL);
		resp = launch_data_new_errno(0);
	} else if (!strcmp(cmd, LAUNCH_KEY_CHECKIN)) {
		if (rmc->c->j) {
			resp = launch_data_copy(rmc->c->j->ldj);
			if (NULL == launch_data_dict_lookup(resp, LAUNCH_JOBKEY_TIMEOUT)) {
				launch_data_t to = launch_data_new_integer(LAUNCHD_MIN_JOB_RUN_TIME);
				launch_data_dict_insert(resp, to, LAUNCH_JOBKEY_TIMEOUT);
			}
			rmc->c->j->checkedin = true;
		} else {
			resp = launch_data_new_errno(EACCES);
		}
	} else if (!strcmp(cmd, LAUNCH_KEY_RELOADTTYS)) {
		update_ttys();
		resp = launch_data_new_errno(0);
	} else if (!strcmp(cmd, LAUNCH_KEY_SHUTDOWN)) {
		launchd_shutdown();
		resp = launch_data_new_errno(0);
	} else if (!strcmp(cmd, LAUNCH_KEY_SINGLEUSER)) {
		launchd_single_user();
		resp = launch_data_new_errno(0);
	} else if (!strcmp(cmd, LAUNCH_KEY_GETJOBS)) {
		resp = job_export_all();
		launch_data_revoke_fds(resp);
	} else if (!strcmp(cmd, LAUNCH_KEY_GETRESOURCELIMITS)) {
		resp = adjust_rlimits(NULL);
	} else if (!strcmp(cmd, LAUNCH_KEY_SETRESOURCELIMITS)) {
		resp = adjust_rlimits(data);
	} else if (!strcmp(cmd, LAUNCH_KEY_GETJOB)) {
		if ((j = job_find(launch_data_get_string(data))) == NULL) {
			resp = launch_data_new_errno(errno);
		} else {
			resp = job_export(j);
			launch_data_revoke_fds(resp);
		}
	} else if (!strcmp(cmd, LAUNCH_KEY_GETJOBWITHHANDLES)) {
		if ((j = job_find(launch_data_get_string(data))) == NULL) {
			resp = launch_data_new_errno(errno);
		} else {
			resp = job_export(j);
		}
	} else if (!strcmp(cmd, LAUNCH_KEY_SETLOGMASK)) {
		resp = launch_data_new_integer(setlogmask(launch_data_get_integer(data)));
	} else if (!strcmp(cmd, LAUNCH_KEY_GETLOGMASK)) {
		int oldmask = setlogmask(LOG_UPTO(LOG_DEBUG));
		resp = launch_data_new_integer(oldmask);
		setlogmask(oldmask);
	} else if (!strcmp(cmd, LAUNCH_KEY_SETUMASK)) {
		resp = launch_data_new_integer(umask(launch_data_get_integer(data)));
	} else if (!strcmp(cmd, LAUNCH_KEY_GETUMASK)) {
		mode_t oldmask = umask(0);
		resp = launch_data_new_integer(oldmask);
		umask(oldmask);
	} else if (!strcmp(cmd, LAUNCH_KEY_GETRUSAGESELF)) {
		struct rusage rusage;
		getrusage(RUSAGE_SELF, &rusage);
		resp = launch_data_new_opaque(&rusage, sizeof(rusage));
	} else if (!strcmp(cmd, LAUNCH_KEY_GETRUSAGECHILDREN)) {
		struct rusage rusage;
		getrusage(RUSAGE_CHILDREN, &rusage);
		resp = launch_data_new_opaque(&rusage, sizeof(rusage));
	} else if (!strcmp(cmd, LAUNCH_KEY_SETSTDOUT)) {
		resp = setstdio(STDOUT_FILENO, data);
	} else if (!strcmp(cmd, LAUNCH_KEY_SETSTDERR)) {
		resp = setstdio(STDERR_FILENO, data);
	} else if (!strcmp(cmd, LAUNCH_KEY_BATCHCONTROL)) {
		batch_job_enable(launch_data_get_bool(data), rmc->c);
		resp = launch_data_new_errno(0);
	} else if (!strcmp(cmd, LAUNCH_KEY_BATCHQUERY)) {
		resp = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(resp, batch_disabler_count == 0);
	}

	rmc->resp = resp;
}

static launch_data_t setstdio(int d, launch_data_t o)
{
	launch_data_t resp = launch_data_new_errno(0);

	if (launch_data_get_type(o) == LAUNCH_DATA_STRING) {
		char **where = &pending_stderr;
		if (d == STDOUT_FILENO)
			where = &pending_stdout;
		if (*where)
			free(*where);
		*where = strdup(launch_data_get_string(o));
	} else if (launch_data_get_type(o) == LAUNCH_DATA_FD) {
		launchd_assumes(dup2(launch_data_get_fd(o), d) != -1);
	} else {
		launch_data_set_errno(resp, EINVAL);
	}

	return resp;
}

static void batch_job_enable(bool e, struct conncb *c)
{
	if (e && c->disabled_batch) {
		batch_disabler_count--;
		c->disabled_batch = 0;
		if (batch_disabler_count == 0)
			kevent_mod(asynckq, EVFILT_READ, EV_ENABLE, 0, 0, &kqasync_callback);
	} else if (!e && !c->disabled_batch) {
		if (batch_disabler_count == 0)
			kevent_mod(asynckq, EVFILT_READ, EV_DISABLE, 0, 0, &kqasync_callback);
		batch_disabler_count++;
		c->disabled_batch = 1;
	}
}

static struct jobcb *job_import(launch_data_t pload)
{
	launch_data_t tmp;
	const char *label;
	struct jobcb *j;
	bool startnow, hasprog = false, hasprogargs = false;

	if ((label = job_get_string(pload, LAUNCH_JOBKEY_LABEL)) == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((j = job_find(label)) != NULL) {
		errno = EEXIST;
		return NULL;
	}

	if (launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAM))
		hasprog = true;
	if (launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAMARGUMENTS))
		hasprogargs = true;

	if (!hasprog && !hasprogargs) {
		errno = EINVAL;
		return NULL;
	}

	j = calloc(1, sizeof(struct jobcb) + strlen(label) + 1);
	strcpy(j->label, label);
	j->ldj = launch_data_copy(pload);
	launch_data_revoke_fds(pload);
	j->kqjob_callback = job_callback;


	if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_ONDEMAND) == NULL) {
		tmp = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(tmp, true);
		launch_data_dict_insert(j->ldj, tmp, LAUNCH_JOBKEY_ONDEMAND);
	}

	SLIST_INSERT_HEAD(&jobs, j, sle);

	j->debug = job_get_bool(j->ldj, LAUNCH_JOBKEY_DEBUG);

	startnow = !job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND);

	if (job_get_bool(j->ldj, LAUNCH_JOBKEY_RUNATLOAD))
		startnow = true;

	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_QUEUEDIRECTORIES))) {
		size_t i;

		j->qdirs_cnt = launch_data_array_get_count(tmp);
		j->qdirs = malloc(sizeof(int) * j->qdirs_cnt);

		for (i = 0; i < j->qdirs_cnt; i++) {
			const char *thepath = launch_data_get_string(launch_data_array_get_index(tmp, i));

			if (-1 == (j->qdirs[i] = _fd(open(thepath, O_EVTONLY))))
				job_log_error(j, LOG_ERR, "open(\"%s\", O_EVTONLY)", thepath);
		}

	}

	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_STARTINTERVAL))) {
		j->start_interval = launch_data_get_integer(tmp);

		if (j->start_interval == 0)
			job_log(j, LOG_WARNING, "StartInterval is zero, ignoring");
		else if (-1 == kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, j->start_interval, &j->kqjob_callback))
			job_log_error(j, LOG_ERR, "adding kevent timer");
	}

	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_STARTCALENDARINTERVAL))) {
		launch_data_t tmp_k;

		j->start_cal_interval = calloc(1, sizeof(struct tm));
		j->start_cal_interval->tm_min = -1;
		j->start_cal_interval->tm_hour = -1;
		j->start_cal_interval->tm_mday = -1;
		j->start_cal_interval->tm_wday = -1;
		j->start_cal_interval->tm_mon = -1;

		if (LAUNCH_DATA_DICTIONARY == launch_data_get_type(tmp)) {
			if ((tmp_k = launch_data_dict_lookup(tmp, LAUNCH_JOBKEY_CAL_MINUTE)))
				j->start_cal_interval->tm_min = launch_data_get_integer(tmp_k);
			if ((tmp_k = launch_data_dict_lookup(tmp, LAUNCH_JOBKEY_CAL_HOUR)))
				j->start_cal_interval->tm_hour = launch_data_get_integer(tmp_k);
			if ((tmp_k = launch_data_dict_lookup(tmp, LAUNCH_JOBKEY_CAL_DAY)))
				j->start_cal_interval->tm_mday = launch_data_get_integer(tmp_k);
			if ((tmp_k = launch_data_dict_lookup(tmp, LAUNCH_JOBKEY_CAL_WEEKDAY)))
				j->start_cal_interval->tm_wday = launch_data_get_integer(tmp_k);
			if ((tmp_k = launch_data_dict_lookup(tmp, LAUNCH_JOBKEY_CAL_MONTH)))
				j->start_cal_interval->tm_mon = launch_data_get_integer(tmp_k);
		}

		job_set_alarm(j);
	}
	
	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_WATCHPATHS))) {
		size_t i;

		j->vnodes_cnt = launch_data_array_get_count(tmp);
		j->vnodes = malloc(sizeof(int) * j->vnodes_cnt);

		for (i = 0; i < j->vnodes_cnt; i++) {
			const char *thepath = launch_data_get_string(launch_data_array_get_index(tmp, i));

			if (-1 == (j->vnodes[i] = _fd(open(thepath, O_EVTONLY))))
				job_log_error(j, LOG_ERR, "open(\"%s\", O_EVTONLY)", thepath);
		}

	}

	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES)))
		launch_data_dict_iterate(tmp, setup_job_env, NULL);
	
	if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
		job_watch(j);

	if (startnow)
		job_start(j);

	return j;
}

struct jobcb *job_find(const char *label)
{
	struct jobcb *j = NULL;

	SLIST_FOREACH(j, &jobs, sle) {
		if (strcmp(j->label, label) == 0)
			break;
	}

	if (j == NULL)
		errno = ESRCH;

	return j;
}

launch_data_t job_export_all(void)
{
	launch_data_t tmp, resp = NULL;
	struct jobcb *j;

	resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	SLIST_FOREACH(j, &jobs, sle) {
		tmp = job_export(j);
		launch_data_dict_insert(resp, tmp, j->label);
	}

	return resp;
}

void usage(FILE *where)
{
	const char *opts = "[-d]";

	if (getuid() == 0)
		opts = "[-d] [-S <type> -U <user>]";

	fprintf(where, "%s: %s [-- command [args ...]]\n", getprogname(), opts);

	fprintf(where, "\t-d          Daemonize.\n");
	fprintf(where, "\t-h          This usage statement.\n");

	if (getuid() == 0) {
		fprintf(where, "\t-S <type>   What type of session to create (Aqua, tty or X11).\n");
		fprintf(where, "\t-U <user>   Which user to create the session as.\n");
	}

	if (where == stdout)
		exit(EXIT_SUCCESS);
}

int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	int q = mainkq;

	if (EVFILT_TIMER == filter || EVFILT_VNODE == filter)
		q = asynckq;

	if (flags & EV_ADD && !launchd_assumes(udata != NULL)) {
		errno = EINVAL;
		return -1;
	}

#ifdef PID1_REAP_ADOPTED_CHILDREN
		if (filter == EVFILT_PROC && getpid() == 1)
			return 0;
#endif
	EV_SET(&kev, ident, filter, flags, fflags, data, udata);
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
	batch_job_enable(true, c);

	SLIST_REMOVE(&connections, c, conncb, sle);
	launchd_close(c->conn);
	free(c);
}

static void setup_job_env(launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	if (LAUNCH_DATA_STRING == launch_data_get_type(obj))
		setenv(key, launch_data_get_string(obj), 1);
}

static void unsetup_job_env(launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	if (LAUNCH_DATA_STRING == launch_data_get_type(obj))
		unsetenv(key);
}

static void job_reap(struct jobcb *j)
{
	bool od = job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND);
	time_t td = time(NULL) - j->start_time;
	bool bad_exit = false;
	int status;

	job_log(j, LOG_DEBUG, "Reaping");

	if (j->execfd) {
		launchd_assumes(close(j->execfd) == 0);
		j->execfd = 0;
	}

#ifdef PID1_REAP_ADOPTED_CHILDREN
	if (getpid() == 1)
		status = pid1_child_exit_status;
	else
#endif
	if (-1 == waitpid(j->p, &status, 0)) {
		job_log_error(j, LOG_ERR, "waitpid(%d, ...)", j->p);
		return;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		job_log(j, LOG_WARNING, "exited with exit code: %d", WEXITSTATUS(status));
		bad_exit = true;
	}

	if (WIFSIGNALED(status)) {
		int s = WTERMSIG(status);
		if (SIGKILL == s || SIGTERM == s) {
			job_log(j, LOG_NOTICE, "exited: %s", strsignal(s));
		} else {
			job_log(j, LOG_WARNING, "exited abnormally: %s", strsignal(s));
			bad_exit = true;
		}
	}

	if (!od) {
		if (td < LAUNCHD_MIN_JOB_RUN_TIME) {
			job_log(j, LOG_WARNING, "respawning too quickly! throttling");
			bad_exit = true;
			j->throttle = true;
		} else if (td >= LAUNCHD_REWARD_JOB_RUN_TIME) {
			job_log(j, LOG_INFO, "lived long enough, forgiving past exit failures");
			j->failed_exits = 0;
		}
	}

	if (bad_exit)
		j->failed_exits++;

	if (j->failed_exits > 0) {
		int failures_left = LAUNCHD_FAILED_EXITS_THRESHOLD - j->failed_exits;
		if (failures_left)
			job_log(j, LOG_WARNING, "%d more failure%s without living at least %d seconds will cause job removal",
					failures_left, failures_left > 1 ? "s" : "", LAUNCHD_REWARD_JOB_RUN_TIME);
	}

	total_children--;
	j->last_exit_status = status;
	j->p = 0;
}

static bool job_restart_fitness_test(struct jobcb *j)
{
	bool od = job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND);

	if (j->firstborn) {
		job_log(j, LOG_DEBUG, "first born died, begin shutdown");
		launchd_shutdown();
		return false;
	} else if (job_get_bool(j->ldj, LAUNCH_JOBKEY_SERVICEIPC) && !j->checkedin) {
		job_log(j, LOG_WARNING, "failed to checkin");
		job_remove(j);
		return false;
	} else if (j->failed_exits >= LAUNCHD_FAILED_EXITS_THRESHOLD) {
		job_log(j, LOG_WARNING, "too many failures in succession");
		job_remove(j);
		return false;
	} else if (od || shutdown_in_progress) {
		if (!od && shutdown_in_progress)
			job_log(j, LOG_NOTICE, "exited while shutdown is in progress, will not restart unless demand requires it");
		job_watch(j);
		return false;
	}

	return true;
}

static void job_callback(void *obj, struct kevent *kev)
{
	struct jobcb *j = obj;
	bool d = j->debug;
	bool startnow = true;
	int oldmask = 0;

	if (d) {
		oldmask = setlogmask(LOG_UPTO(LOG_DEBUG));
		job_log(j, LOG_DEBUG, "log level debug temporarily enabled while processing job");
	}

	if (kev->filter == EVFILT_PROC) {
		job_reap(j);

		startnow = job_restart_fitness_test(j);

		if (startnow && j->throttle) {
			j->throttle = false;
			job_log(j, LOG_WARNING, "will restart in %d seconds", LAUNCHD_MIN_JOB_RUN_TIME);
			if (-1 == kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_ADD|EV_ONESHOT,
						NOTE_SECONDS, LAUNCHD_MIN_JOB_RUN_TIME, &j->kqjob_callback)) {
				job_log_error(j, LOG_WARNING, "failed to setup timer callback!, starting now!");
			} else {
				startnow = false;
			}
		}
	} else if (kev->filter == EVFILT_TIMER && (void *)kev->ident == j->start_cal_interval) {
		job_set_alarm(j);
	} else if (kev->filter == EVFILT_VNODE) {
		size_t i;
		const char *thepath = NULL;

		for (i = 0; i < j->vnodes_cnt; i++) {
			if (j->vnodes[i] == (int)kev->ident) {
				launch_data_t ld_vnodes = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_WATCHPATHS);

				thepath = launch_data_get_string(launch_data_array_get_index(ld_vnodes, i));

				job_log(j, LOG_DEBUG, "watch path modified: %s", thepath);

				if ((NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE) & kev->fflags) {
					job_log(j, LOG_DEBUG, "watch path invalidated: %s", thepath);
					launchd_assumes(close(j->vnodes[i]) == 0);
					j->vnodes[i] = -1; /* this will get fixed in job_watch() */
				}
			}
		}

		for (i = 0; i < j->qdirs_cnt; i++) {
			if (j->qdirs[i] == (int)kev->ident) {
				launch_data_t ld_qdirs = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_QUEUEDIRECTORIES);
				int dcc_r;

				thepath = launch_data_get_string(launch_data_array_get_index(ld_qdirs, i));

				job_log(j, LOG_DEBUG, "queue directory modified: %s", thepath);

				if (-1 == (dcc_r = dir_has_files(thepath))) {
					job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", thepath);
				} else if (0 == dcc_r) {
					job_log(j, LOG_DEBUG, "spurious wake up, directory empty: %s", thepath);
					startnow = false;
				}
			}
		}
		/* if we get here, then the vnodes either wasn't a qdir, or if it was, it has entries in it */
	} else if (kev->filter == EVFILT_READ && (int)kev->ident == j->execfd) {
		if (kev->data > 0) {
			int e;

			read(j->execfd, &e, sizeof(e));
			errno = e;
			job_log_error(j, LOG_ERR, "execve()");
			job_remove(j);
			j = NULL;
			startnow = false;
		} else {
			launchd_assumes(close(j->execfd) == 0);
			j->execfd = 0;
		}
		startnow = false;
	}

	if (startnow)
		job_start(j);

	if (d) {
		/* the job might have been removed, must not call job_log() */
		syslog(LOG_DEBUG, "restoring original log mask");
		setlogmask(oldmask);
	}
}

static void job_start(struct jobcb *j)
{
	int spair[2];
	int execspair[2];
	bool sipc;
	char nbuf[64];
	pid_t c;

	job_log(j, LOG_DEBUG, "Starting");

	if (j->p) {
		job_log(j, LOG_DEBUG, "already running");
		return;
	}

	j->checkedin = false;

	sipc = job_get_bool(j->ldj, LAUNCH_JOBKEY_SERVICEIPC);

	if (job_get_bool(j->ldj, LAUNCH_JOBKEY_INETDCOMPATIBILITY))
		sipc = true;

	if (sipc)
		socketpair(AF_UNIX, SOCK_STREAM, 0, spair);

	socketpair(AF_UNIX, SOCK_STREAM, 0, execspair);

	time(&j->start_time);

	switch (c = launchd_fork()) {
	case -1:
		job_log_error(j, LOG_ERR, "fork() failed, will try again in one second");
		launchd_assumes(close(execspair[0]) == 0);
		launchd_assumes(close(execspair[1]) == 0);
		if (sipc) {
			launchd_assumes(close(spair[0]) == 0);
			launchd_assumes(close(spair[1]) == 0);
		}
		if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
			job_ignore(j);
		break;
	case 0:
		launchd_assumes(close(execspair[0]) == 0);
		/* wait for our parent to say they've attached a kevent to us */
		read(_fd(execspair[1]), &c, sizeof(c));
		if (j->firstborn) {
			setpgid(getpid(), getpid());
			if (isatty(STDIN_FILENO)) {
				if (tcsetpgrp(STDIN_FILENO, getpid()) == -1)
					job_log_error(j, LOG_WARNING, "tcsetpgrp()");
			}
		}

		if (sipc) {
			launchd_assumes(close(spair[0]) == 0);
			sprintf(nbuf, "%d", spair[1]);
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
		}
		job_start_child(j, execspair[1]);
		break;
	default:
		j->p = c;
		total_children++;
		launchd_assumes(close(execspair[1]) == 0);
		j->execfd = _fd(execspair[0]);
		if (sipc) {
			launchd_assumes(close(spair[1]) == 0);
			ipc_open(_fd(spair[0]), j);
		}
		if (kevent_mod(j->execfd, EVFILT_READ, EV_ADD, 0, 0, &j->kqjob_callback) == -1)
			job_log_error(j, LOG_ERR, "kevent_mod(j->execfd): %m");
		if (kevent_mod(c, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &j->kqjob_callback) == -1) {
			job_log_error(j, LOG_ERR, "kevent()");
			job_reap(j);
		} else {
			if (job_get_bool(j->ldj, LAUNCH_JOBKEY_ONDEMAND))
				job_ignore(j);
		}
		/* this unblocks the child and avoids a race
		 * between the above fork() and the kevent_mod() */
		write(j->execfd, &c, sizeof(c));
		break;
	}
}

void
job_start_child(struct jobcb *j, int execfd)
{
	launch_data_t ldpa = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
	bool inetcompat = job_get_bool(j->ldj, LAUNCH_JOBKEY_INETDCOMPATIBILITY);
	size_t i, argv_cnt;
	const char **argv, *file2exec = "/usr/libexec/launchproxy";
	int r;
	bool hasprog = false;

	job_setup_attributes(j);

	if (ldpa) {
		argv_cnt = launch_data_array_get_count(ldpa);
		argv = alloca((argv_cnt + 2) * sizeof(char *));
		for (i = 0; i < argv_cnt; i++)
			argv[i + 1] = launch_data_get_string(launch_data_array_get_index(ldpa, i));
		argv[argv_cnt + 1] = NULL;
	} else {
		argv = alloca(3 * sizeof(char *));
		argv[1] = job_get_string(j->ldj, LAUNCH_JOBKEY_PROGRAM);
		argv[2] = NULL;
	}

	if (job_get_string(j->ldj, LAUNCH_JOBKEY_PROGRAM))
		hasprog = true;

	if (inetcompat) {
		argv[0] = file2exec;
	} else {
		argv++;
		file2exec = job_get_file2exec(j->ldj);
	}

	if (hasprog) {
		r = execv(file2exec, (char *const*)argv);
	} else {
		r = execvp(file2exec, (char *const*)argv);
	}

	if (-1 == r) {
		write(execfd, &errno, sizeof(errno));
		job_log_error(j, LOG_ERR, "execv%s(\"%s\", ...)", hasprog ? "" : "p", file2exec);
	}
	exit(EXIT_FAILURE);
}

static void job_setup_attributes(struct jobcb *j)
{
	launch_data_t srl = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_SOFTRESOURCELIMITS);
	launch_data_t hrl = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_HARDRESOURCELIMITS);
	bool inetcompat = job_get_bool(j->ldj, LAUNCH_JOBKEY_INETDCOMPATIBILITY);
	launch_data_t tmp;
	size_t i;
	const char *tmpstr;
	struct group *gre = NULL;
	gid_t gre_g = 0;
	static const struct {
		const char *key;
		int val;
	} limits[] = {
		{ LAUNCH_JOBKEY_RESOURCELIMIT_CORE,    RLIMIT_CORE    },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_CPU,     RLIMIT_CPU     },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_DATA,    RLIMIT_DATA    },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_FSIZE,   RLIMIT_FSIZE   },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_MEMLOCK, RLIMIT_MEMLOCK },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_NOFILE,  RLIMIT_NOFILE  },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_NPROC,   RLIMIT_NPROC   },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_RSS,     RLIMIT_RSS     },
		{ LAUNCH_JOBKEY_RESOURCELIMIT_STACK,   RLIMIT_STACK   },
	};

	setpriority(PRIO_PROCESS, 0, job_get_integer(j->ldj, LAUNCH_JOBKEY_NICE));

	if (srl || hrl) {
		for (i = 0; i < (sizeof(limits) / sizeof(limits[0])); i++) {
			struct rlimit rl;

			if (getrlimit(limits[i].val, &rl) == -1) {
				job_log_error(j, LOG_WARNING, "getrlimit()");
				continue;
			}

			if (hrl)
				rl.rlim_max = job_get_integer(hrl, limits[i].key);
			if (srl)
				rl.rlim_cur = job_get_integer(srl, limits[i].key);

			if (setrlimit(limits[i].val, &rl) == -1)
				job_log_error(j, LOG_WARNING, "setrlimit()");
		}
	}

	if (!inetcompat && job_get_bool(j->ldj, LAUNCH_JOBKEY_SESSIONCREATE))
		launchd_SessionCreate();

	if (job_get_bool(j->ldj, LAUNCH_JOBKEY_LOWPRIORITYIO)) {
		int lowprimib[] = { CTL_KERN, KERN_PROC_LOW_PRI_IO };
		int val = 1;

		if (sysctl(lowprimib, sizeof(lowprimib) / sizeof(lowprimib[0]), NULL, NULL,  &val, sizeof(val)) == -1)
			job_log_error(j, LOG_WARNING, "sysctl(\"%s\")", "kern.proc_low_pri_io");
	}
	if ((tmpstr = job_get_string(j->ldj, LAUNCH_JOBKEY_ROOTDIRECTORY))) {
		chroot(tmpstr);
		chdir(".");
	}
	if ((tmpstr = job_get_string(j->ldj, LAUNCH_JOBKEY_GROUPNAME))) {
		gre = getgrnam(tmpstr);
		if (gre) {
			gre_g = gre->gr_gid;
			if (-1 == setgid(gre_g)) {
				job_log_error(j, LOG_ERR, "setgid(%d)", gre_g);
				exit(EXIT_FAILURE);
			}
		} else {
			job_log(j, LOG_ERR, "getgrnam(\"%s\") failed", tmpstr);
			exit(EXIT_FAILURE);
		}
	}
	if ((tmpstr = job_get_string(j->ldj, LAUNCH_JOBKEY_USERNAME))) {
		struct passwd *pwe = getpwnam(tmpstr);
		if (pwe) {
			uid_t pwe_u = pwe->pw_uid;
			uid_t pwe_g = pwe->pw_gid;

			if (pwe->pw_expire && time(NULL) >= pwe->pw_expire) {
				job_log(j, LOG_ERR, "expired account: %s", tmpstr);
				exit(EXIT_FAILURE);
			}
			if (job_get_bool(j->ldj, LAUNCH_JOBKEY_INITGROUPS)) {
				if (-1 == initgroups(tmpstr, gre ? gre_g : pwe_g)) {
					job_log_error(j, LOG_ERR, "initgroups()");
					exit(EXIT_FAILURE);
				}
			}
			if (!gre) {
				if (-1 == setgid(pwe_g)) {
					job_log_error(j, LOG_ERR, "setgid(%d)", pwe_g);
					exit(EXIT_FAILURE);
				}
			}
			if (-1 == setuid(pwe_u)) {
				job_log_error(j, LOG_ERR, "setuid(%d)", pwe_u);
				exit(EXIT_FAILURE);
			}
		} else {
			job_log(j, LOG_WARNING, "getpwnam(\"%s\") failed", tmpstr);
			exit(EXIT_FAILURE);
		}
	}
	if ((tmpstr = job_get_string(j->ldj, LAUNCH_JOBKEY_WORKINGDIRECTORY)))
		chdir(tmpstr);
	if (launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_UMASK))
		umask(job_get_integer(j->ldj, LAUNCH_JOBKEY_UMASK));
	if ((tmpstr = job_get_string(j->ldj, LAUNCH_JOBKEY_STANDARDOUTPATH))) {
		int sofd = open(tmpstr, O_WRONLY|O_APPEND|O_CREAT, DEFFILEMODE);
		if (sofd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", tmpstr);
		} else {
			launchd_assumes(dup2(sofd, STDOUT_FILENO) != -1);
			launchd_assumes(close(sofd) == 0);
		}
	}
	if ((tmpstr = job_get_string(j->ldj, LAUNCH_JOBKEY_STANDARDERRORPATH))) {
		int sefd = open(tmpstr, O_WRONLY|O_APPEND|O_CREAT, DEFFILEMODE);
		if (sefd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", tmpstr);
		} else {
			launchd_assumes(dup2(sefd, STDERR_FILENO) != -1);
			launchd_assumes(close(sefd) == 0);
		}
	}
	if ((tmp = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES)))
		launch_data_dict_iterate(tmp, setup_job_env, NULL);

	setsid();
}

#ifdef PID1_REAP_ADOPTED_CHILDREN
__private_extern__ int pid1_child_exit_status = 0;
static void pid1waitpid(void)
{
	pid_t p;

	while ((p = waitpid(-1, &pid1_child_exit_status, WNOHANG)) > 0) {
		if (!launchd_check_pid(p)) {
			if (!mach_init_check_pid(p))
				init_check_pid(p);
		}
	}
}
#endif

static void launchd_shutdown(void)
{
	shutdown_in_progress = true;

	launchd_assumes(kevent_mod(asynckq, EVFILT_READ, EV_DISABLE, 0, 0, &kqasync_callback) != -1);

	mach_start_shutdown();

	if (getpid() == 1)
		catatonia();
}

static void launchd_single_user(void)
{
	int tries;

	launchd_shutdown();

	kill(-1, SIGTERM);

	for (tries = 0; tries < 10; tries++) {
		sleep(1);
		if (kill(-1, 0) == -1 && errno == ESRCH)
			goto out;
	}

	syslog(LOG_WARNING, "Gave up waiting for processes to exit while going to single user mode, sending SIGKILL");
	kill(-1, SIGKILL);

out:
	re_exec_in_single_user_mode = true;
}

static void signal_callback(void *obj __attribute__((unused)), struct kevent *kev)
{
	switch (kev->ident) {
	case SIGHUP:
		if (getpid() == 1)
			update_ttys();
		reload_launchd_config();
		break;
	case SIGTERM:
		launchd_shutdown();
		break;
#ifdef PID1_REAP_ADOPTED_CHILDREN
	case SIGCHLD:
		/* <rdar://problem/3632556> Please automatically reap processes reparented to PID 1 */
		if (getpid() == 1) 
			pid1waitpid();
		break;
#endif
	default:
		break;
	} 
}

static void fs_callback(void)
{
	static bool mounted_volfs = false;

	if (1 != getpid())
		mounted_volfs = true;

	if (pending_stdout) {
		int fd = open(pending_stdout, O_CREAT|O_APPEND|O_WRONLY, DEFFILEMODE);
		if (fd != -1) {
			launchd_assumes(dup2(fd, STDOUT_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			free(pending_stdout);
			pending_stdout = NULL;
		}
	}
	if (pending_stderr) {
		int fd = open(pending_stderr, O_CREAT|O_APPEND|O_WRONLY, DEFFILEMODE);
		if (fd != -1) {
			launchd_assumes(dup2(fd, STDERR_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			free(pending_stderr);
			pending_stderr = NULL;
		}
	}

	if (!mounted_volfs) {
		int r = mount("volfs", VOLFSDIR, MNT_RDONLY, NULL);

		if (-1 == r && errno == ENOENT) {
			mkdir(VOLFSDIR, ACCESSPERMS & ~(S_IWUSR|S_IWGRP|S_IWOTH));
			r = mount("volfs", VOLFSDIR, MNT_RDONLY, NULL);
		}

		if (-1 == r) {
			syslog(LOG_WARNING, "mount(\"%s\", \"%s\", ...): %m", "volfs", VOLFSDIR);
		} else {
			mounted_volfs = true;
		}
	}

	if (!launchd_inited)
		launchd_server_init();
}

static void readcfg_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	int status;

#ifdef PID1_REAP_ADOPTED_CHILDREN
	if (getpid() == 1)
		status = pid1_child_exit_status;
	else
#endif
	if (!launchd_assumes(waitpid(readcfg_pid, &status, 0) != -1))
		return;

	readcfg_pid = 0;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status))
			syslog(LOG_WARNING, "Unable to read launchd.conf: launchctl exited with status: %d", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		syslog(LOG_WARNING, "Unable to read launchd.conf: launchctl exited abnormally: %s", strsignal(WTERMSIG(status)));
	} else {
		syslog(LOG_WARNING, "Unable to read launchd.conf: launchctl exited abnormally");
	}
}

static void reload_launchd_config(void)
{
	struct stat sb;
	static char *ldconf = PID1LAUNCHD_CONF;
	const char *h = getenv("HOME");

	if (h && ldconf == PID1LAUNCHD_CONF)
		asprintf(&ldconf, "%s/%s", h, LAUNCHD_CONF);

	if (!ldconf)
		return;

	if (lstat(ldconf, &sb) == 0) {
		int spair[2];
		launchd_assumes(socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == 0);
		readcfg_pid = launchd_fork();
		if (readcfg_pid == 0) {
			char nbuf[100];
			launchd_assumes(close(spair[0]) == 0);
			sprintf(nbuf, "%d", spair[1]);
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
			int fd = open(ldconf, O_RDONLY);
			if (fd == -1) {
				syslog(LOG_ERR, "open(\"%s\"): %m", ldconf);
				exit(EXIT_FAILURE);
			}
			launchd_assumes(dup2(fd, STDIN_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			launchd_assumes(execl(LAUNCHCTL_PATH, LAUNCHCTL_PATH, NULL) != -1);
			exit(EXIT_FAILURE);
		} else if (readcfg_pid == -1) {
			launchd_assumes(close(spair[0]) == 0);
			launchd_assumes(close(spair[1]) == 0);
			syslog(LOG_ERR, "fork(): %m");
			readcfg_pid = 0;
		} else {
			launchd_assumes(close(spair[1]) == 0);
			ipc_open(_fd(spair[0]), NULL);
			launchd_assumes(kevent_mod(readcfg_pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqreadcfg_callback) != -1);
		}
	}
}

struct jobcb *conceive_firstborn(char *argv[], const char *session_user)
{
	launch_data_t d = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_t args = launch_data_alloc(LAUNCH_DATA_ARRAY);
	launch_data_t l = launch_data_new_string("com.apple.launchd.firstborn");
	struct jobcb *j;
	size_t i;

	if (argv[0] == NULL && session_user) {
		launch_data_t ed = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		struct passwd *pw = getpwnam(session_user);
		const char *sh = (pw && pw->pw_shell) ? pw->pw_shell : _PATH_BSHELL;
		const char *wd = (pw && pw->pw_dir) ? pw->pw_dir : NULL;
		const char *un = (pw && pw->pw_name) ? pw->pw_name : NULL;
		const char *tty, *ttyn = ttyname(STDIN_FILENO);
		char *p, arg0[PATH_MAX] = "-";

		strcpy(arg0 + 1, (p = strrchr(sh, '/')) ?  p + 1 : sh);

		if (wd) {
			launch_data_dict_insert(d, launch_data_new_string(wd), LAUNCH_JOBKEY_WORKINGDIRECTORY);
			launch_data_dict_insert(ed, launch_data_new_string(wd), "HOME");
		}
		if (sh) {
			launch_data_dict_insert(ed, launch_data_new_string(sh), "SHELL");
		}
		if (un) {
			launch_data_dict_insert(ed, launch_data_new_string(un), "USER");
			launch_data_dict_insert(ed, launch_data_new_string(un), "LOGNAME");
		}
		if (ttyn && NULL == getenv("TERM")) {
			struct ttyent *t;
			const char *term;

			if ((tty = strrchr(ttyn, '/')))
				tty++;
			else
				tty = ttyn;

			if ((t = getttynam(tty)))
				term = t->ty_type;
			else
				term = "su"; /* I don't know why login(8) defaulted to this value... */

			launch_data_dict_insert(ed, launch_data_new_string(term), "TERM");
		}

		launch_data_dict_insert(d, launch_data_new_string(sh), LAUNCH_JOBKEY_PROGRAM);
		launch_data_dict_insert(d, ed, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES);
		launch_data_array_set_index(args, launch_data_new_string(arg0), 0);
	} else {
		for (i = 0; *argv; argv++, i++)
			launch_data_array_set_index(args, launch_data_new_string(*argv), i);
	}

	launch_data_dict_insert(d, args, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
	launch_data_dict_insert(d, l, LAUNCH_JOBKEY_LABEL);

	j = job_import(d);

	launch_data_free(d);

	j->firstborn = true;

	return j;
}

static void loopback_setup(void)
{
	struct ifaliasreq ifra;
	struct in6_aliasreq ifra6;
	struct ifreq ifr;
	int s, s6;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	launchd_assumes((s = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	launchd_assumes((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) != -1);

	if (launchd_assumes(ioctl(s, SIOCGIFFLAGS, &ifr) != -1)) {
		ifr.ifr_flags |= IFF_UP;
		launchd_assumes(ioctl(s, SIOCSIFFLAGS, &ifr) != -1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	if (launchd_assumes(ioctl(s6, SIOCGIFFLAGS, &ifr) != -1)) {
		ifr.ifr_flags |= IFF_UP;
		launchd_assumes(ioctl(s6, SIOCSIFFLAGS, &ifr) != -1);
	}

	memset(&ifra, 0, sizeof(ifra));
	strcpy(ifra.ifra_name, "lo0");

	((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr = htonl(IN_CLASSA_NET);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_len = sizeof(struct sockaddr_in);

	launchd_assumes(ioctl(s, SIOCAIFADDR, &ifra) != -1);

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

	launchd_assumes(ioctl(s6, SIOCAIFADDR_IN6, &ifra6) != -1);
 
	launchd_assumes(close(s) == 0);
	launchd_assumes(close(s6) == 0);
}

static void workaround3048875(int argc, char *argv[])
{
	int i;
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

static launch_data_t adjust_rlimits(launch_data_t in)
{
	static struct rlimit *l = NULL;
	static size_t lsz = sizeof(struct rlimit) * RLIM_NLIMITS;
	struct rlimit *ltmp;
	size_t i,ltmpsz;

	if (l == NULL) {
		l = malloc(lsz);
		for (i = 0; i < RLIM_NLIMITS; i++)
			launchd_assumes(getrlimit(i, l + i) != -1);
	}

	if (in) {
		ltmp = launch_data_get_opaque(in);
		ltmpsz = launch_data_get_opaque_size(in);

		if (ltmpsz > lsz) {
			syslog(LOG_WARNING, "Too much rlimit data sent!");
			ltmpsz = lsz;
		}
		
		for (i = 0; i < (ltmpsz / sizeof(struct rlimit)); i++) {
			if (ltmp[i].rlim_cur == l[i].rlim_cur && ltmp[i].rlim_max == l[i].rlim_max)
				continue;

			if (readcfg_pid && getpid() == 1) {
				int gmib[] = { CTL_KERN, KERN_MAXPROC };
				int pmib[] = { CTL_KERN, KERN_MAXPROCPERUID };
				const char *gstr = "kern.maxproc";
				const char *pstr = "kern.maxprocperuid";
				int gval = ltmp[i].rlim_max;
				int pval = ltmp[i].rlim_cur;
				switch (i) {
				case RLIMIT_NOFILE:
					gmib[1] = KERN_MAXFILES;
					pmib[1] = KERN_MAXFILESPERPROC;
					gstr = "kern.maxfiles";
					pstr = "kern.maxfilesperproc";
					break;
				case RLIMIT_NPROC:
					/* kernel will not clamp to this value, we must */
					if (gval > (2048 + 20))
						gval = 2048 + 20;
					break;
				default:
					break;
				}

				if (gval > 0) {
					launchd_assumes(sysctl(gmib, 2, NULL, NULL, &gval, sizeof(gval)) != -1);
				} else {
					syslog(LOG_WARNING, "sysctl(\"%s\"): can't be zero", gstr);
				}
				if (pval > 0) {
					launchd_assumes(sysctl(pmib, 2, NULL, NULL, &pval, sizeof(pval)) != -1);
				} else {
					syslog(LOG_WARNING, "sysctl(\"%s\"): can't be zero", pstr);
				}
			}
			launchd_assumes(setrlimit(i, ltmp + i) != -1);
			/* the kernel may have clamped the values we gave it */
			launchd_assumes(getrlimit(i, l + i) != -1);
		}
	}

	return launch_data_new_opaque(l, sizeof(struct rlimit) * RLIM_NLIMITS);
}

__private_extern__ void launchd_SessionCreate(void)
{
	OSStatus (*sescr)(SessionCreationFlags flags, SessionAttributeBits attributes);
	void *seclib;

	if (launchd_assumes((seclib = dlopen(SECURITY_LIB, RTLD_LAZY)) != NULL)) {
		if (launchd_assumes((sescr = dlsym(seclib, "SessionCreate")) != NULL))
			launchd_assumes(sescr(0, 0) == noErr);
		launchd_assumes(dlclose(seclib) != -1);
	}
}

static int dir_has_files(const char *path)
{
	DIR *dd = opendir(path);
	struct dirent *de;
	bool r = 0;

	if (!dd)
		return -1;

	while ((de = readdir(dd))) {
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			r = 1;
			break;
		}
	}

	launchd_assumes(closedir(dd) == 0);
	return r;
}

static void job_set_alarm(struct jobcb *j)
{
	struct tm otherlatertm, latertm, *nowtm;
	time_t later, otherlater = 0, now = time(NULL);

	nowtm = localtime(&now);

	latertm = *nowtm;

	latertm.tm_sec = 0;
	latertm.tm_isdst = -1;


	if (-1 != j->start_cal_interval->tm_min)
		latertm.tm_min = j->start_cal_interval->tm_min;
	if (-1 != j->start_cal_interval->tm_hour)
		latertm.tm_hour = j->start_cal_interval->tm_hour;

	otherlatertm = latertm;

	if (-1 != j->start_cal_interval->tm_mday)
		latertm.tm_mday = j->start_cal_interval->tm_mday;
	if (-1 != j->start_cal_interval->tm_mon)
		latertm.tm_mon = j->start_cal_interval->tm_mon;

	/* cron semantics are fun */
	if (-1 != j->start_cal_interval->tm_wday) {
		int delta, realwday = j->start_cal_interval->tm_wday;

		if (realwday == 7)
			realwday = 0;
		
		delta = realwday - nowtm->tm_wday;
		
		/* Now Later Delta Desired
		 *   0     6     6       6
		 *   6     0    -6  7 + -6
		 *   1     5     4       4
		 *   5     1    -4  7 + -4
		 */
		if (delta > 0) {
			otherlatertm.tm_mday += delta;
		} else if (delta < 0) {
			otherlatertm.tm_mday += 7 + delta;
		} else if (-1 != j->start_cal_interval->tm_hour && otherlatertm.tm_hour <= nowtm->tm_hour) {
			otherlatertm.tm_mday += 7;
		} else if (-1 != j->start_cal_interval->tm_min && otherlatertm.tm_min <= nowtm->tm_min) {
			otherlatertm.tm_hour++;
		} else {
			otherlatertm.tm_min++;
		}

		otherlater = mktime(&otherlatertm);
	}

	if (-1 != j->start_cal_interval->tm_mon && latertm.tm_mon <= nowtm->tm_mon) {
		latertm.tm_year++;
	} else if (-1 != j->start_cal_interval->tm_mday && latertm.tm_mday <= nowtm->tm_mday) {
		latertm.tm_mon++;
	} else if (-1 != j->start_cal_interval->tm_hour && latertm.tm_hour <= nowtm->tm_hour) {
		latertm.tm_mday++;
	} else if (-1 != j->start_cal_interval->tm_min && latertm.tm_min <= nowtm->tm_min) {
		latertm.tm_hour++;
	} else {
		latertm.tm_min++;
	}

	later = mktime(&latertm);

	if (otherlater) {
		if (-1 != j->start_cal_interval->tm_mday)
			later = later < otherlater ? later : otherlater;
		else
			later = otherlater;
	}

	if (-1 == kevent_mod((uintptr_t)j->start_cal_interval, EVFILT_TIMER, EV_ADD, NOTE_ABSOLUTE|NOTE_SECONDS, later, &j->kqjob_callback)) {
		job_log_error(j, LOG_ERR, "adding kevent alarm");
	} else {
		job_log(j, LOG_INFO, "scheduled to run again at %s", ctime(&later));
	}
}

static void job_log_error(struct jobcb *j, int pri, const char *msg, ...)
{
	size_t newmsg_sz = strlen(msg) + strlen(j->label) + 200;
	char *newmsg = alloca(newmsg_sz);
	va_list ap;

	sprintf(newmsg, "%s: %s: %s", j->label, msg, strerror(errno));

	va_start(ap, msg);

	vsyslog(pri, newmsg, ap);

	va_end(ap);
}

static void job_log(struct jobcb *j, int pri, const char *msg, ...)
{
	size_t newmsg_sz = strlen(msg) + sizeof(": ") + strlen(j->label);
	char *newmsg = alloca(newmsg_sz);
	va_list ap;

	sprintf(newmsg, "%s: %s", j->label, msg);

	va_start(ap, msg);

	vsyslog(pri, newmsg, ap);

	va_end(ap);
}

static void async_callback(void)
{
	struct timespec timeout = { 0, 0 };
	struct kevent kev;

	if (launchd_assumes(kevent(asynckq, NULL, 0, &kev, 1, &timeout) == 1))
		(*((kq_callback *)kev.udata))(kev.udata, &kev);
}

static void testfd_or_openfd(int fd, const char *path, int flags)
{
	int tmpfd;

	if (-1 != (tmpfd = dup(fd))) {
		launchd_assumes(close(tmpfd) == 0);
	} else {
		if (-1 == (tmpfd = open(path, flags))) {
			syslog(LOG_ERR, "open(\"%s\", ...): %m", path);
		} else if (tmpfd != fd) {
			launchd_assumes(dup2(tmpfd, fd) != -1);
			launchd_assumes(close(tmpfd) == 0);
		}
	}
}
