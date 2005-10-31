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

#include "launch.h"
#include "launch_priv.h"
#include "launchd.h"
#include "launchd_core_logic.h"
#include "launchd_unix_ipc.h"

#define PID1LAUNCHD_CONF "/etc/launchd.conf"
#define LAUNCHD_CONF ".launchd.conf"
#define LAUNCHCTL_PATH "/bin/launchctl"
#define SECURITY_LIB "/System/Library/Frameworks/Security.framework/Versions/A/Security"
#define VOLFSDIR "/.vol"

extern char **environ;

static void async_callback(void);
static void signal_callback(void *, struct kevent *);
static void fs_callback(void);
static void pfsystem_callback(void *, struct kevent *);

static kq_callback kqasync_callback = (kq_callback)async_callback;
static kq_callback kqsignal_callback = signal_callback;
static kq_callback kqfs_callback = (kq_callback)fs_callback;
static kq_callback kqshutdown_callback = (kq_callback)launchd_shutdown;
static kq_callback kqpfsystem_callback = pfsystem_callback;

#ifdef PID1_REAP_ADOPTED_CHILDREN
static void pid1waitpid(void);
#endif
static void pid1_magic_init(bool sflag, bool vflag, bool xflag);

static void usage(FILE *where);

static void loopback_setup(void);
static void workaround3048875(int argc, char *const *argv);
static void testfd_or_openfd(int fd, const char *path, int flags);
static bool get_network_state(void);
static void monitor_networking_state(void);

static int mainkq = 0;
static int asynckq = 0;
static bool re_exec_in_single_user_mode = false;
static char *pending_stdout = NULL;
static char *pending_stderr = NULL;
static struct jobcb *fbj = NULL;
static struct jobcb *rlcj = NULL;

sigset_t blocked_signals = 0;
bool shutdown_in_progress = false;
bool network_up = false;
int batch_disabler_count = 0;

int main(int argc, char *const *argv)
{
	static const int sigigns[] = { SIGHUP, SIGINT, SIGPIPE, SIGALRM,
		SIGTERM, SIGURG, SIGTSTP, SIGTSTP, SIGCONT, /*SIGCHLD,*/
		SIGTTIN, SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2
	};
	bool sflag = false, xflag = false, vflag = false, dflag = false;
	char ldconf[PATH_MAX] = PID1LAUNCHD_CONF;
	const char *h = getenv("HOME");
	const char *session_type = NULL;
	const char *optargs = NULL;
	struct kevent kev;
	struct stat sb;
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

	testfd_or_openfd(STDIN_FILENO, _PATH_DEVNULL, O_RDONLY|O_NOCTTY);
	testfd_or_openfd(STDOUT_FILENO, _PATH_DEVNULL, O_WRONLY|O_NOCTTY);
	testfd_or_openfd(STDERR_FILENO, _PATH_DEVNULL, O_WRONLY|O_NOCTTY);

	/* main phase two: parse arguments */

	if (getpid() == 1) {
		optargs = "svx";
	} else {
		optargs = "S:dh";
	}

	while ((ch = getopt(argc, argv, optargs)) != -1) {
		switch (ch) {
		case 'S': session_type = optarg; break;	/* what type of session we're creating */
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

	/* main phase three: get the party started */

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

	mach_init_init();

	if (h)
		sprintf(ldconf, "%s/%s", h, LAUNCHD_CONF);

	rlcj = job_new(root_job, READCONF_LABEL, LAUNCHCTL_PATH, NULL, ldconf, MACH_PORT_NULL);
	launchd_assert(rlcj != NULL);

	if (argv[0])
		fbj = job_new(root_job, FIRSTBORN_LABEL, NULL, (const char *const *)argv, NULL, MACH_PORT_NULL);

	if (NULL == getenv("PATH"))
		setenv("PATH", _PATH_STDPATH, 1);

	if (getpid() == 1) {
		pid1_magic_init(sflag, vflag, xflag);
	} else {
		ipc_server_init();
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

		if (pp == 1)
			exit(EXIT_SUCCESS);

		ker = kevent_mod(pp, EVFILT_PROC, EV_ADD, 0, 0, &kqshutdown_callback);

		if (ker == -1)
			exit(launchd_assumes(errno == ESRCH) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	if (stat(ldconf, &sb) == 0)
		job_start(rlcj);

	if (fbj)
		job_start(fbj);

	for (;;) {
		if (getpid() == 1 && !job_active(rlcj))
			init_pre_kevent();

		if (shutdown_in_progress && total_children == 0) {
			mach_init_reap();

			shutdown_in_progress = false;

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
	int memmib[2] = { CTL_HW, HW_MEMSIZE };
	int mvnmib[2] = { CTL_KERN, KERN_MAXVNODES };
	int hnmib[2] = { CTL_KERN, KERN_HOSTNAME };
	uint64_t mem = 0;
	uint32_t mvn;
	size_t memsz = sizeof(mem);
#ifdef KERN_TFP
	struct group *tfp_gr;
		
	if (launchd_assumes((tfp_gr = getgrnam("procview")) != NULL)) {
		int tfp_r_mib[3] = { CTL_KERN, KERN_TFP, KERN_TFP_READ_GROUP };
		gid_t tfp_r_gid = tfp_gr->gr_gid;
		launchd_assumes(sysctl(tfp_r_mib, 3, NULL, NULL, &tfp_r_gid, sizeof(tfp_r_gid)) != -1);
	}

	if (launchd_assumes((tfp_gr = getgrnam("procmod")) != NULL)) {
		int tfp_rw_mib[3] = { CTL_KERN, KERN_TFP, KERN_TFP_RW_GROUP };
		gid_t tfp_rw_gid = tfp_gr->gr_gid;
		launchd_assumes(sysctl(tfp_rw_mib, 3, NULL, NULL, &tfp_rw_gid, sizeof(tfp_rw_gid)) != -1);
	}
#endif

	setpriority(PRIO_PROCESS, 0, -1);

	if (setsid() == -1)
		syslog(LOG_ERR, "setsid(): %m");

	if (chdir("/") == -1)
		syslog(LOG_ERR, "chdir(\"/\"): %m");

	if (sysctl(memmib, 2, &mem, &memsz, NULL, 0) == -1) {
		syslog(LOG_WARNING, "sysctl(\"%s\"): %m", "hw.physmem");
	} else {
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

int _fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}

#ifdef PID1_REAP_ADOPTED_CHILDREN
int pid1_child_exit_status = 0;
static void pid1waitpid(void)
{
	pid_t p;

	while ((p = waitpid(-1, &pid1_child_exit_status, WNOHANG)) > 0)
		launchd_blame(job_reap_pid(root_job, p) || init_check_pid(p), 3632556);
}
#endif

void
launchd_shutdown(void)
{
	shutdown_in_progress = true;

	launchd_assumes(close(asynckq) != -1);
	
	job_remove_all_inactive(root_job);

	if (getpid() == 1)
		catatonia();
}

void
launchd_single_user(void)
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
		job_start(rlcj);
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

void
fs_callback(void)
{
	static bool mounted_volfs = false;

	if (1 != getpid())
		mounted_volfs = true;

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

	ipc_server_init();
}

void
loopback_setup(void)
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

	launchd_blame(ioctl(s, SIOCAIFADDR, &ifra) != -1, 4282331);

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

	launchd_blame(ioctl(s6, SIOCAIFADDR_IN6, &ifra6) != -1, 4282331);
 
	launchd_assumes(close(s) == 0);
	launchd_assumes(close(s6) == 0);
}

void
workaround3048875(int argc, char *const *argv)
{
	int correct_argc = 1;
	char **ap, *newargv[100], *p = argv[1];

	if (argc == 1 || argc > 2)
		return;

	newargv[0] = argv[0];
	for (ap = newargv + 1; ap < &newargv[100]; ap++, correct_argc++) {
		if ((*ap = strsep(&p, " \t")) == NULL)
			break;
		if (**ap == '\0') {
			*ap = NULL;
			break;
		}
	}

	if (launchd_blame(argc == correct_argc, 3048875))
		return;

	execv(newargv[0], newargv);
}

void
launchd_SessionCreate(void)
{
	OSStatus (*sescr)(SessionCreationFlags flags, SessionAttributeBits attributes);
	void *seclib;

	if (launchd_assumes((seclib = dlopen(SECURITY_LIB, RTLD_LAZY)) != NULL)) {
		if (launchd_assumes((sescr = dlsym(seclib, "SessionCreate")) != NULL))
			launchd_assumes(sescr(0, 0) == noErr);
		launchd_assumes(dlclose(seclib) != -1);
	}
}

void
async_callback(void)
{
	struct timespec timeout = { 0, 0 };
	struct kevent kev;

	if (launchd_assumes(kevent(asynckq, NULL, 0, &kev, 1, &timeout) == 1))
		(*((kq_callback *)kev.udata))(kev.udata, &kev);
}

void
testfd_or_openfd(int fd, const char *path, int flags)
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

launch_data_t                   
launchd_setstdio(int d, launch_data_t o)
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

void
batch_job_enable(bool e, struct conncb *c)
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

bool
get_network_state(void)
{
	struct ifaddrs *ifa, *ifai;
	bool up = false;

	if (!launchd_assumes(getifaddrs(&ifa) != -1))
		return network_up;

	for (ifai = ifa; ifai; ifai = ifai->ifa_next) {
		if (!(ifai->ifa_flags & IFF_UP))
			continue;
		if (ifai->ifa_flags & IFF_LOOPBACK)
			continue;
		if (ifai->ifa_addr->sa_family != AF_INET && ifai->ifa_addr->sa_family != AF_INET6)
			continue;
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

	if (!launchd_assumes(pfs != -1))
		return;

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
