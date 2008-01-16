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
#include <sys/reboot.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
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
#include <sched.h>

#include "libbootstrap_public.h"
#include "libvproc_public.h"
#include "libvproc_internal.h"
#include "liblaunch_public.h"

#include "launchd_runtime.h"
#include "launchd_core_logic.h"
#include "launchd_unix_ipc.h"

#define LAUNCHD_CONF ".launchd.conf"
#define SECURITY_LIB "/System/Library/Frameworks/Security.framework/Versions/A/Security"


extern char **environ;

INTERNAL_ABI static void pfsystem_callback(void *, struct kevent *);

static kq_callback kqpfsystem_callback = pfsystem_callback;

static void pid1_magic_init(void);

static void testfd_or_openfd(int fd, const char *path, int flags);
static bool get_network_state(void);
static void monitor_networking_state(void);
static void fatal_signal_handler(int sig, siginfo_t *si, void *uap);
static void handle_pid1_crashes_separately(void);

static bool re_exec_in_single_user_mode;
static void *crash_addr;
static pid_t crash_pid;

bool shutdown_in_progress;
bool fake_shutdown_in_progress;
bool network_up;

int
main(int argc, char *const *argv)
{
	bool sflag = false;
	int ch;

	testfd_or_openfd(STDIN_FILENO, _PATH_DEVNULL, O_RDONLY);
	testfd_or_openfd(STDOUT_FILENO, _PATH_DEVNULL, O_WRONLY);
	testfd_or_openfd(STDERR_FILENO, _PATH_DEVNULL, O_WRONLY);

	while ((ch = getopt(argc, argv, "s")) != -1) {
		switch (ch) {
		case 's': sflag = true; break;	/* single user */
		case '?': /* we should do something with the global optopt variable here */
		default:
			fprintf(stderr, "%s: ignoring unknown arguments\n", getprogname());
			break;
		}
	}

	if (getpid() != 1 && getppid() != 1) {
		fprintf(stderr, "%s: This program is not meant to be run directly.\n", getprogname());
		exit(EXIT_FAILURE);
	}

	launchd_runtime_init();

	if (NULL == getenv("PATH")) {
		setenv("PATH", _PATH_STDPATH, 1);
	}

	if (pid1_magic) {
		pid1_magic_init();
	} else {
		ipc_server_init();
	}

	monitor_networking_state();

	if (pid1_magic) {
		handle_pid1_crashes_separately();
	}

	jobmgr_init(sflag);

	launchd_runtime_init2();

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

/* This hack forces the dynamic linker to resolve these symbols ASAP */
static __attribute__((unused)) typeof(sync) *__junk_dyld_trick1 = sync;
static __attribute__((unused)) typeof(sleep) *__junk_dyld_trick2 = sleep;
static __attribute__((unused)) typeof(reboot) *__junk_dyld_trick3 = reboot;

void
fatal_signal_handler(int sig, siginfo_t *si, void *uap __attribute__((unused)))
{
	const char *doom_why = "at instruction";
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
		break;
	case -1:
		break;
	}

	switch (sig) {
	default:
	case 0:
		break;
	case SIGBUS:
	case SIGSEGV:
		doom_why = "trying to read/write";
	case SIGILL:
	case SIGFPE:
		runtime_syslog(LOG_EMERG, "We crashed %s: %p (sent by PID %u)", doom_why, crash_addr, crash_pid);
		sync();
		sleep(3);
		reboot(0);
		break;
	}
}

void
pid1_magic_init(void)
{
	launchd_assumes(setsid() != -1);
	launchd_assumes(chdir("/") != -1);
	launchd_assumes(setlogin("root") != -1);
	launchd_assumes(mount("fdesc", "/dev", MNT_UNION, NULL) != -1);
}


INTERNAL_ABI int
_fd(int fd)
{
	if (fd >= 0) {
		launchd_assumes(fcntl(fd, F_SETFD, 1) != -1);
	}
	return fd;
}

INTERNAL_ABI void
launchd_shutdown(void)
{
	int64_t now;

	if (shutdown_in_progress) {
		return;
	}

	shutdown_in_progress = true;

	if (pid1_magic) {
		/*
		 * When this changes to a more sustainable API, update this:
		 * http://howto.apple.com/db.cgi?Debugging_Apps_Non-Responsive_At_Shutdown
		 */
		runtime_setlogmask(LOG_UPTO(LOG_DEBUG));
	}

	runtime_log_push();

	now = runtime_get_wall_time();

	runtime_syslog(LOG_NOTICE, "Shutdown began at: %lld.%06llu", now / USEC_PER_SEC, now % USEC_PER_SEC);

	launchd_assert(jobmgr_shutdown(root_jobmgr) != NULL);
}

INTERNAL_ABI void
launchd_single_user(void)
{
	runtime_syslog(LOG_NOTICE, "Going to single-user mode");

	re_exec_in_single_user_mode = true;

	launchd_shutdown();

	sleep(3);

	runtime_kill(-1, SIGKILL);
}

INTERNAL_ABI void
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
		launchd_assumes(runtime_close(tmpfd) == 0);
	} else {
		if (-1 == (tmpfd = open(path, flags | O_NOCTTY, DEFFILEMODE))) {
			runtime_syslog(LOG_ERR, "open(\"%s\", ...): %m", path);
		} else if (tmpfd != fd) {
			launchd_assumes(dup2(tmpfd, fd) != -1);
			launchd_assumes(runtime_close(tmpfd) == 0);
		}
	}
}

bool
get_network_state(void)
{
	struct ifaddrs *ifa, *ifai;
	bool up = false;
	int r;

	/* Workaround 4978696: getifaddrs() reports false ENOMEM */
	while ((r = getifaddrs(&ifa)) == -1 && errno == ENOMEM) {
		runtime_syslog(LOG_DEBUG, "Worked around bug: 4978696");
		launchd_assumes(sched_yield() != -1);
	}

	if (!launchd_assumes(r != -1)) {
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
		runtime_close(pfs);
		return;
	}

	launchd_assumes(kevent_mod(pfs, EVFILT_READ, EV_ADD, 0, 0, &kqpfsystem_callback) != -1);
}

INTERNAL_ABI void
pfsystem_callback(void *obj __attribute__((unused)), struct kevent *kev)
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

INTERNAL_ABI void
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

	runtime_syslog(LOG_NOTICE, "Bug: %s:%u (%s):%u: %s", file, line, buf, saved_errno, test);
}
