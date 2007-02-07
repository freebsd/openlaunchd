/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

static const char *const __rcs_file_version__ = "$Revision$";

#include "config.h"
#include "launchd.h"

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
#include <sys/kern_event.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <ifaddrs.h>
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
#include <setjmp.h>
#include <spawn.h>

#include "libbootstrap_public.h"
#include "libvproc_public.h"
#include "libvproc_internal.h"
#include "liblaunch_public.h"
#include "liblaunch_private.h"

#include "launchd_runtime.h"
#include "launchd_core_logic.h"
#include "launchd_unix_ipc.h"

#define PID1LAUNCHD_CONF "/etc/launchd.conf"
#define LAUNCHD_CONF ".launchd.conf"
#define SECURITY_LIB "/System/Library/Frameworks/Security.framework/Versions/A/Security"

extern char **environ;

static void signal_callback(void *, struct kevent *);
static void ppidexit_callback(void);
static void debugshutdown_callback(void);
static void pfsystem_callback(void *, struct kevent *);

static kq_callback kqsignal_callback = signal_callback;
static kq_callback kqppidexit_callback = (kq_callback)ppidexit_callback;
static kq_callback kqdebugshutdown_callback = (kq_callback)debugshutdown_callback;
static kq_callback kqpfsystem_callback = pfsystem_callback;

static void pid1_magic_init(bool sflag);

static void usage(FILE *where);

static void testfd_or_openfd(int fd, const char *path, int flags);
static bool get_network_state(void);
static void monitor_networking_state(void);
static void fatal_signal_handler(int sig, siginfo_t *si, void *uap);
static void handle_pid1_crashes_separately(void);

static bool re_exec_in_single_user_mode = false;
static job_t rlcj = NULL;
static jmp_buf doom_doom_doom;
static void *crash_addr;
static pid_t crash_pid;
static const char *launchctl_bootstrap_tool[] = { "/bin/launchctl", /* "bootstrap", */ NULL };

sigset_t blocked_signals = 0;
bool shutdown_in_progress = false;
bool debug_shutdown_hangs = false;
bool network_up = false;
int batch_disabler_count = 0;

int
main(int argc, char *const *argv)
{
	static const int sigigns[] = { SIGHUP, SIGINT, SIGPIPE, SIGALRM,
		SIGTERM, SIGURG, SIGTSTP, SIGTSTP, SIGCONT, /*SIGCHLD,*/
		SIGTTIN, SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2
	};
	bool sflag = false, dflag = false, Dflag = false;
	char ldconf[PATH_MAX] = PID1LAUNCHD_CONF;
	const char *h = getenv("HOME");
	const char *session_type = NULL;
	const char *optargs = NULL;
	job_t fbj = NULL;
	struct stat sb;
	size_t i, checkin_fdcnt = 0;
	int *checkin_fds = NULL;
	mach_port_t checkin_mport = MACH_PORT_NULL;
	int ch, ker, logopts;

	testfd_or_openfd(STDIN_FILENO, _PATH_DEVNULL, O_RDONLY);
	testfd_or_openfd(STDOUT_FILENO, _PATH_DEVNULL, O_WRONLY);
	testfd_or_openfd(STDERR_FILENO, _PATH_DEVNULL, O_WRONLY);

	/* main() phase one: sanitize the process */

	if (getpid() != 1) {
		launch_data_t ldresp, ldmsg = launch_data_new_string(LAUNCH_KEY_CHECKIN);

		if ((ldresp = launch_msg(ldmsg))) {
			if (launch_data_get_type(ldresp) == LAUNCH_DATA_DICTIONARY) {
				const char *ldlabel = launch_data_get_string(launch_data_dict_lookup(ldresp, LAUNCH_JOBKEY_LABEL));
				launch_data_t tmp;

				if ((tmp = launch_data_dict_lookup(ldresp, LAUNCH_JOBKEY_SOCKETS))) {
					if ((tmp = launch_data_dict_lookup(tmp, "LaunchIPC"))) {
						checkin_fdcnt = launch_data_array_get_count(tmp);
						checkin_fds = alloca(sizeof(int) * checkin_fdcnt);
						for (i = 0; i < checkin_fdcnt; i++) {
							checkin_fds[i] = _fd(launch_data_get_fd(launch_data_array_get_index(tmp, i)));
						}
					}
				}
				if ((tmp = launch_data_dict_lookup(ldresp, LAUNCH_JOBKEY_MACHSERVICES))) {
					if ((tmp = launch_data_dict_lookup(tmp, ldlabel))) {
						checkin_mport = launch_data_get_machport(tmp);
					}
				}
			}
			launch_data_free(ldresp);
		} else {
			int sigi, fdi, dts = getdtablesize();
			sigset_t emptyset;

			/* We couldn't check-in.
			 *
			 * Assume the worst and clean up whatever mess our parent process left us with...
			 */

			for (fdi = STDERR_FILENO + 1; fdi < dts; fdi++)
				close(fdi);
			for (sigi = 1; sigi < NSIG; sigi++) {
				switch (sigi) {
				case SIGKILL:
				case SIGSTOP:
					break;
				default:
					launchd_assumes(signal(sigi, SIG_DFL) != SIG_ERR);
					break;
				}
			}
			sigemptyset(&emptyset);
			launchd_assumes(sigprocmask(SIG_SETMASK, &emptyset, NULL) == 0);
		}

		launch_data_free(ldmsg);
	}

	launchd_runtime_init();

	/* main() phase two: parse arguments */

	if (getpid() == 1) {
		optargs = "s";
	} else {
		optargs = "DS:dh";
	}

	while ((ch = getopt(argc, argv, optargs)) != -1) {
		switch (ch) {
		case 'S': session_type = optarg; break;	/* what type of session we're creating */
		case 'D': Dflag = true;   break;	/* debug */
		case 'd': dflag = true;   break;	/* daemonize */
		case 's': sflag = true;   break;	/* single user */
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

	/* main phase three: get the party started */

	if (dflag) {
		launchd_assumes(daemon(0, 0) == 0);
	}

	logopts = LOG_PID|LOG_CONS;
	if (Dflag) {
		logopts |= LOG_PERROR;
	}

	openlog(getprogname(), logopts, LOG_LAUNCHD);
	setlogmask(LOG_UPTO(Dflag ? LOG_DEBUG : LOG_NOTICE));

	sigemptyset(&blocked_signals);

	for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
		launchd_assumes(kevent_mod(sigigns[i], EVFILT_SIGNAL, EV_ADD, 0, 0, &kqsignal_callback) != -1);
		sigaddset(&blocked_signals, sigigns[i]);
		launchd_assumes(signal(sigigns[i], SIG_IGN) != SIG_ERR);
	}

	/* sigh... ignoring SIGCHLD has side effects: we can't call wait*() */
	launchd_assert(kevent_mod(SIGCHLD, EVFILT_SIGNAL, EV_ADD, 0, 0, &kqsignal_callback) != -1);

	mach_init_init(checkin_mport);

	if (h) {
		snprintf(ldconf, sizeof(ldconf), "%s/%s", h, LAUNCHD_CONF);
	}

	rlcj = job_new(root_jobmgr, READCONF_LABEL, NULL, launchctl_bootstrap_tool, ldconf);
	launchd_assert(rlcj != NULL);

	if (argv[0]) {
		fbj = job_new(root_jobmgr, FIRSTBORN_LABEL, NULL, (const char *const *)argv, NULL);
	}

	if (NULL == getenv("PATH")) {
		setenv("PATH", _PATH_STDPATH, 1);
	}

	if (getpid() == 1) {
		pid1_magic_init(sflag);
	} else {
		ipc_server_init(checkin_fds, checkin_fdcnt);
	}

	monitor_networking_state();

	if (session_type) {
		pid_t pp = getppid();

		/* As a per session launchd, we need to exit if our parent dies.
		 *
		 * Normally, in Unix, SIGHUP would cause us to exit, but we're a
		 * daemon, and daemons use SIGHUP to signal the need to reread
		 * configuration files. "Weee."
		 */

		if (pp == 1) {
			exit(EXIT_SUCCESS);
		}

		ker = kevent_mod(pp, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqppidexit_callback);

		if (ker == -1) {
			exit(launchd_assumes(errno == ESRCH) ? EXIT_SUCCESS : EXIT_FAILURE);
		}
	}

	/*
	 * We cannot stat() anything in the home directory right now.
	 *
	 * The per-user launchd can easily be demand launched by the tool doing
	 * the mount of the home directory. The result is an ugly deadlock.
	 *
	 * We hope to someday have a non-blocking stat(), but for now, we have
	 * to skip it.
	 */
	if (!h && stat(ldconf, &sb) == 0) {
		rlcj = job_dispatch(rlcj, true);
	}

	if (fbj) {
		fbj = job_dispatch(fbj, true);
	}

	char *doom_why = "at instruction";
	switch (setjmp(doom_doom_doom)) {
		case 0:
			break;
		case SIGBUS:
		case SIGSEGV:
			doom_why = "trying to read/write";
		case SIGILL:
		case SIGFPE:
			syslog(LOG_EMERG, "We crashed %s: %p (sent by PID %u)", doom_why, crash_addr, crash_pid);
		default:
			sync();
			sleep(3);
			/* the kernel will panic() when PID 1 exits */
			_exit(EXIT_FAILURE);
			/* we should never get here */
			reboot(0);
			/* or here either */
			break;
	}

	if (getpid() == 1) {
		handle_pid1_crashes_separately();

		if (!job_active(rlcj)) {
			init_pre_kevent();
		}
	}

	launchd_runtime();
}

void
handle_pid1_crashes_separately(void)
{
	struct sigaction fsa;

	fsa.sa_sigaction = fatal_signal_handler;
	fsa.sa_flags = SA_SIGINFO;
	sigemptyset(&fsa.sa_mask);

	launchd_assumes(sigaction(SIGILL, &fsa, NULL) != -1);
	launchd_assumes(sigaction(SIGFPE, &fsa, NULL) != -1);
	launchd_assumes(sigaction(SIGBUS, &fsa, NULL) != -1);
	launchd_assumes(sigaction(SIGSEGV, &fsa, NULL) != -1);
}

#define PID1_CRASH_LOGFILE "/var/log/launchd-pid1.crash"

void
fatal_signal_handler(int sig, siginfo_t *si, void *uap)
{
	char *sample_args[] = { "/usr/bin/sample", "1", "1", "-file", PID1_CRASH_LOGFILE, NULL };
	pid_t sample_p;
	int wstatus;

	crash_addr = si->si_addr;
	crash_pid = si->si_pid;

	unlink(PID1_CRASH_LOGFILE);

	switch ((sample_p = vfork())) {
	case 0:
		execve(sample_args[0], sample_args, environ);
		_exit(EXIT_FAILURE);
		break;
	default:
		waitpid(sample_p, &wstatus, 0);
		sync();
		break;
	case -1:
		break;
	}

	longjmp(doom_doom_doom, sig);
}

void
pid1_magic_init(bool sflag)
{
	launchd_assumes(setsid() != -1);
	launchd_assumes(chdir("/") != -1);
	launchd_assumes(setlogin("root") != -1);
	launchd_assumes(mount("fdesc", "/dev", MNT_UNION, NULL) != -1);

	init_boot(sflag);
}


void
usage(FILE *where)
{
	const char *opts = "[-d]";

	if (getuid() == 0) {
		opts = "[-d] [-S <type> -U <user>]";
	}

	fprintf(where, "%s: %s [-- command [args ...]]\n", getprogname(), opts);

	fprintf(where, "\t-d          Daemonize.\n");
	fprintf(where, "\t-h          This usage statement.\n");

	if (getuid() == 0) {
		fprintf(where, "\t-S <type>   What type of session to create (Aqua, tty or X11).\n");
		fprintf(where, "\t-U <user>   Which user to create the session as.\n");
	}

	if (where == stdout) {
		exit(EXIT_SUCCESS);
	}
}

int
_fd(int fd)
{
	if (fd >= 0) {
		launchd_assumes(fcntl(fd, F_SETFD, 1) != -1);
	}
	return fd;
}

void
ppidexit_callback(void)
{
	syslog(LOG_INFO, "Parent process exited");

	launchd_shutdown();

	/* Let's just bail for now. We should really try to wait for jobs to exit first. */
	exit(EXIT_SUCCESS);
}

void
launchd_shutdown(void)
{
	if (shutdown_in_progress) {
		return;
	}

	shutdown_in_progress = true;

#if 0
	struct stat sb;

	if (stat("/var/db/debugShutdownHangs", &sb) != -1) {
		/*
		 * When this changes to a more sustainable API, update this:
		 * http://howto.apple.com/db.cgi?Debugging_Apps_Non-Responsive_At_Shutdown
		 */
		debug_shutdown_hangs = true;
	}
#else
	if (getpid() == 1) {
		launchd_assumes(kevent_mod((uintptr_t)debugshutdown_callback,
					EVFILT_TIMER, EV_ADD|EV_ONESHOT, NOTE_SECONDS, 5, &kqdebugshutdown_callback) != -1);
	}
#endif

	rlcj = NULL;

	jobmgr_remove_all_inactive(root_jobmgr);
}

void
launchd_single_user(void)
{
	syslog(LOG_NOTICE, "Going to single-user mode");

	re_exec_in_single_user_mode = true;

	launchd_shutdown();

	sleep(3);

	kill(-1, SIGKILL);
}

static void signal_callback(void *obj __attribute__((unused)), struct kevent *kev)
{
	syslog(LOG_DEBUG, "Received signal: %u", kev->ident);

	switch (kev->ident) {
	case SIGHUP:
		if (rlcj) {
			rlcj = job_dispatch(rlcj, true);
		}
		break;
	case SIGTERM:
		launchd_shutdown();
		break;
	default:
		break;
	} 
}

void
launchd_SessionCreate(void)
{
	OSStatus (*sescr)(SessionCreationFlags flags, SessionAttributeBits attributes);
	void *seclib;

	if (launchd_assumes((seclib = dlopen(SECURITY_LIB, RTLD_LAZY)) != NULL)) {
		if (launchd_assumes((sescr = dlsym(seclib, "SessionCreate")) != NULL)) {
			launchd_assumes(sescr(0, 0) == noErr);
		}
		launchd_assumes(dlclose(seclib) != -1);
	}
}

void
testfd_or_openfd(int fd, const char *path, int flags)
{
	int tmpfd;

	if (-1 != (tmpfd = dup(fd))) {
		launchd_assumes(close(tmpfd) == 0);
	} else {
		if (-1 == (tmpfd = open(path, flags | O_NOCTTY, DEFFILEMODE))) {
			syslog(LOG_ERR, "open(\"%s\", ...): %m", path);
		} else if (tmpfd != fd) {
			launchd_assumes(dup2(tmpfd, fd) != -1);
			launchd_assumes(close(tmpfd) == 0);
		}
	}
}

launch_data_t                   
launchd_setstdio(int d, launch_data_t o)
{
	launch_data_t resp = launch_data_new_errno(0);

	if (launch_data_get_type(o) == LAUNCH_DATA_STRING) {
		switch (d) {
		case STDOUT_FILENO:
			jobmgr_set_stdout(root_jobmgr, launch_data_get_string(o));
			break;
		case STDERR_FILENO:
			jobmgr_set_stderr(root_jobmgr, launch_data_get_string(o));
			break;
		default:
			launch_data_set_errno(resp, EINVAL);
			break;
		}
	} else {
		launch_data_set_errno(resp, EINVAL);
	}

	return resp;
}

void
batch_job_enable(bool e, struct conncb *c)
{
	if (e && c->disabled_batch) {
		batch_disabler_count--;
		c->disabled_batch = 0;
		if (batch_disabler_count == 0) {
			runtime_force_on_demand(false);
		}
	} else if (!e && !c->disabled_batch) {
		if (batch_disabler_count == 0) {
			runtime_force_on_demand(true);
		}
		batch_disabler_count++;
		c->disabled_batch = 1;
	}
}

bool
get_network_state(void)
{
	struct ifaddrs *ifa, *ifai;
	bool up = false;

	if (!launchd_assumes(getifaddrs(&ifa) != -1)) {
		return network_up;
	}

	for (ifai = ifa; ifai; ifai = ifai->ifa_next) {
		if (!(ifai->ifa_flags & IFF_UP)) {
			continue;
		}
		if (ifai->ifa_flags & IFF_LOOPBACK) {
			continue;
		}
		if (ifai->ifa_addr->sa_family != AF_INET && ifai->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		up = true;
		break;
	}

	freeifaddrs(ifa);

	return up;
}

void
monitor_networking_state(void)
{
	int pfs = _fd(socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT));
	struct kev_request kev_req;

	network_up = get_network_state();

	if (!launchd_assumes(pfs != -1)) {
		return;
	}

	memset(&kev_req, 0, sizeof(kev_req));
	kev_req.vendor_code = KEV_VENDOR_APPLE;
	kev_req.kev_class = KEV_NETWORK_CLASS;

	if (!launchd_assumes(ioctl(pfs, SIOCSKEVFILT, &kev_req) != -1)) {
		close(pfs);
		return;
	}

	launchd_assumes(kevent_mod(pfs, EVFILT_READ, EV_ADD, 0, 0, &kqpfsystem_callback) != -1);
}

void
pfsystem_callback(void *obj, struct kevent *kev)
{
	bool new_networking_state;
	char buf[1024];

	launchd_assumes(read(kev->ident, &buf, sizeof(buf)) != -1);

	new_networking_state = get_network_state();

	if (new_networking_state != network_up) {
		network_up = new_networking_state;
		jobmgr_dispatch_all_semaphores(root_jobmgr);
	}
}

void
_log_launchd_bug(const char *rcs_rev, const char *path, unsigned int line, const char *test)
{
	int saved_errno = errno;
	char buf[100];
	const char *file = strrchr(path, '/');
	char *rcs_rev_tmp = strchr(rcs_rev, ' ');

	if (!file) {
		file = path;
	} else {
		file += 1;
	}

	if (!rcs_rev_tmp) {
		strlcpy(buf, rcs_rev, sizeof(buf));
	} else {
		strlcpy(buf, rcs_rev_tmp + 1, sizeof(buf));
		rcs_rev_tmp = strchr(buf, ' ');
		if (rcs_rev_tmp) {
			*rcs_rev_tmp = '\0';
		}
	}

	syslog(LOG_NOTICE, "Bug: %s:%u (%s):%u: %s", file, line, buf, saved_errno, test);
}

void
launchd_post_kevent(void)
{
	if (shutdown_in_progress && jobmgr_is_idle(root_jobmgr)) {
		shutdown_in_progress = false;

		if (getpid() != 1) {
			exit(EXIT_SUCCESS);
		} else if (re_exec_in_single_user_mode) {
			re_exec_in_single_user_mode = false;
			kill(-1, SIGKILL); /* One last time, just to clear the room */
			launchd_assumes(execl("/sbin/launchd", "/sbin/launchd", "-s", NULL) != -1);
		}
	}
	if (getpid() == 1) {
		if (rlcj && job_active(rlcj)) {
			return;
		}
		init_pre_kevent();
	}
}

void
debugshutdown_callback(void)
{
	char *sdd_args[] = { "/usr/libexec/shutdown_debugger", NULL };
	pid_t sddp;

	if (launchd_assumes(posix_spawn(&sddp, sdd_args[0], NULL, NULL, sdd_args, environ) == 0)) {
		launchd_assumes(kevent_mod(sddp, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) != -1);
	}
}
