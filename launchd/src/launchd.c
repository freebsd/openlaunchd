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

#include "bootstrap_public.h"
#include "bootstrap_private.h"
#include "launch.h"
#include "launch_priv.h"
#include "launchd.h"
#include "launchd_runtime.h"
#include "launchd_core_logic.h"
#include "launchd_unix_ipc.h"

#define PID1LAUNCHD_CONF "/etc/launchd.conf"
#define LAUNCHD_CONF ".launchd.conf"
#define LAUNCHCTL_PATH "/bin/launchctl"
#define SECURITY_LIB "/System/Library/Frameworks/Security.framework/Versions/A/Security"

extern char **environ;

static void signal_callback(void *, struct kevent *);
static void fs_callback(void);
static void ppidexit_callback(void);
static void pfsystem_callback(void *, struct kevent *);

static kq_callback kqsignal_callback = signal_callback;
static kq_callback kqfs_callback = (kq_callback)fs_callback;
static kq_callback kqppidexit_callback = (kq_callback)ppidexit_callback;
static kq_callback kqpfsystem_callback = pfsystem_callback;

static void pid1_magic_init(bool sflag);

static void usage(FILE *where);

static void testfd_or_openfd(int fd, const char *path, int flags);
static bool get_network_state(void);
static void monitor_networking_state(void);
static void fatal_signal_handler(int sig, siginfo_t *si, void *uap);

static bool re_exec_in_single_user_mode = false;
static char *pending_stdout = NULL;
static char *pending_stderr = NULL;
static job_t rlcj = NULL;
static jmp_buf doom_doom_doom;
static void *crash_addr;

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
	struct sigaction fsa;
	bool sflag = false, dflag = false, Dflag = false;
	mach_msg_type_number_t l2l_name_cnt = 0, l2l_port_cnt = 0;
	name_array_t l2l_names = NULL;
	mach_port_array_t l2l_ports = NULL;
	char ldconf[PATH_MAX] = PID1LAUNCHD_CONF;
	const char *h = getenv("HOME");
	const char *session_type = NULL;
	const char *optargs = NULL;
	job_t fbj = NULL;
	struct stat sb;
	size_t i, checkin_fdcnt = 0;
	int *checkin_fds = NULL;
	mach_port_t req_mport = MACH_PORT_NULL;
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

	if (session_type && strcmp(session_type, "Aqua") == 0) {
		mach_port_t newparent;

		launchd_assert(bootstrap_parent(bootstrap_port, &newparent) == BOOTSTRAP_SUCCESS);

		launchd_assert(_launchd_to_launchd(bootstrap_port, &req_mport, &checkin_mport,
					&l2l_names, &l2l_name_cnt, &l2l_ports, &l2l_port_cnt) == BOOTSTRAP_SUCCESS);

		launchd_assert(l2l_name_cnt == l2l_port_cnt);

		task_set_bootstrap_port(mach_task_self(), newparent);
		launchd_assumes(mach_port_deallocate(mach_task_self(), bootstrap_port) == KERN_SUCCESS);
		bootstrap_port = newparent;
	}

	mach_init_init(req_mport, checkin_mport, l2l_names, l2l_ports, l2l_name_cnt);

	if (l2l_names) {
		mig_deallocate((vm_address_t)l2l_names, l2l_name_cnt * sizeof(l2l_names[0]));
	}
	if (l2l_ports) {
		mig_deallocate((vm_address_t)l2l_ports, l2l_port_cnt * sizeof(l2l_ports[0]));
	}

	if (h) {
		sprintf(ldconf, "%s/%s", h, LAUNCHD_CONF);
	}

	rlcj = job_new(root_job, READCONF_LABEL, LAUNCHCTL_PATH, NULL, ldconf, MACH_PORT_NULL);
	launchd_assert(rlcj != NULL);

	if (argv[0]) {
		fbj = job_new(root_job, FIRSTBORN_LABEL, NULL, (const char *const *)argv, NULL, MACH_PORT_NULL);
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

		if (pp == 1) {
			exit(EXIT_SUCCESS);
		}

		ker = kevent_mod(pp, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqppidexit_callback);

		if (ker == -1) {
			exit(launchd_assumes(errno == ESRCH) ? EXIT_SUCCESS : EXIT_FAILURE);
		}
	}

	if (stat(ldconf, &sb) == 0) {
		job_dispatch(rlcj, true);
	}

	if (fbj) {
		job_dispatch(fbj, true);
	}

	if (getpid() == 1 && !job_active(rlcj)) {
		init_pre_kevent();
	}

	switch (setjmp(doom_doom_doom)) {
	case SIGILL:
	case SIGFPE:
		syslog(LOG_EMERG, "We crashed at instruction: %p", crash_addr);
		abort();
	case SIGBUS:
	case SIGSEGV:
		syslog(LOG_EMERG, "We crashed trying to read/write: %p", crash_addr);
		abort();
	default:
		abort();
	case 0:
		break;
	}

	fsa.sa_sigaction = fatal_signal_handler;
	fsa.sa_flags = SA_SIGINFO;
	sigemptyset(&fsa.sa_mask);

	launchd_assumes(sigaction(SIGILL, &fsa, NULL) != -1);
	launchd_assumes(sigaction(SIGFPE, &fsa, NULL) != -1);
	launchd_assumes(sigaction(SIGBUS, &fsa, NULL) != -1);
	launchd_assumes(sigaction(SIGSEGV, &fsa, NULL) != -1);

	launchd_runtime();
}

void
fatal_signal_handler(int sig, siginfo_t *si, void *uap)
{
	crash_addr = si->si_addr;
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
	struct stat sb;

	if (shutdown_in_progress) {
		return;
	}

	shutdown_in_progress = true;

	if (stat("/var/db/debugShutdownHangs", &sb) != -1) {
		// When this changes to a more sustainable API, update this:
		// http://howto.apple.com/db.cgi?Debugging_Apps_Non-Responsive_At_Shutdown
		debug_shutdown_hangs = true;
	}

	rlcj = NULL;

	job_remove_all_inactive(root_job);

	if (getpid() == 1) {
		catatonia();
	}
}

void
launchd_single_user(void)
{
	int tries;

	launchd_shutdown();

	kill(-1, SIGTERM);

	for (tries = 0; tries < 10; tries++) {
		sleep(1);
		if (kill(-1, 0) == -1 && errno == ESRCH) {
			goto out;
		}
	}

	syslog(LOG_WARNING, "Gave up waiting for processes to exit while going to single user mode, sending SIGKILL");
	kill(-1, SIGKILL);

out:
	re_exec_in_single_user_mode = true;
}

static void signal_callback(void *obj __attribute__((unused)), struct kevent *kev)
{
	syslog(LOG_DEBUG, "Received signal: %u", kev->ident);

	switch (kev->ident) {
	case SIGHUP:
		if (rlcj) {
			job_dispatch(rlcj, true);
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
fs_callback(void)
{
	if (pending_stdout) {
		int fd = open(pending_stdout, O_CREAT|O_APPEND|O_WRONLY|O_NOCTTY, DEFFILEMODE);
		if (fd != -1) {
			launchd_assumes(dup2(fd, STDOUT_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			free(pending_stdout);
			pending_stdout = NULL;
		}
	}
	if (pending_stderr) {
		int fd = open(pending_stderr, O_CREAT|O_APPEND|O_WRONLY|O_NOCTTY, DEFFILEMODE);
		if (fd != -1) {
			launchd_assumes(dup2(fd, STDERR_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			free(pending_stderr);
			pending_stderr = NULL;
		}
	}

	ipc_server_init(NULL, 0);
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
		char **where = &pending_stderr;

		if (d == STDOUT_FILENO) {
			where = &pending_stdout;
		}
		if (*where) {
			free(*where);
		}
		*where = strdup(launch_data_get_string(o));
	} else if (launch_data_get_type(o) == LAUNCH_DATA_FD) {
		launchd_assumes(dup2(launch_data_get_fd(o), d) != -1);
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
		job_dispatch_all_other_semaphores(root_job, NULL);
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

bool
progeny_check(pid_t p)
{
	pid_t selfpid = getpid();

	while (p != selfpid && p != 1) {
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, p };
		size_t miblen = sizeof(mib) / sizeof(mib[0]);
		struct kinfo_proc kp;
		size_t kplen = sizeof(kp);

		if (launchd_assumes(sysctl(mib, miblen, &kp, &kplen, NULL, 0) != -1) && launchd_assumes(kplen == sizeof(kp))) {
			p = kp.kp_eproc.e_ppid;
		} else {
			return false;
		}
	}

	if (p == selfpid) {
		return true;
	}

	return false;
}

void
launchd_post_kevent(void)
{
	if (shutdown_in_progress && total_children == 0) {
		shutdown_in_progress = false;

		if (getpid() != 1) {
			exit(EXIT_SUCCESS);
		} else if (re_exec_in_single_user_mode) {
			re_exec_in_single_user_mode = false;
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
