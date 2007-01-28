/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
/*-
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Donn Seeley at Berkeley Software Design, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static const char *const __rcs_file_version__ = "$Revision$";

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ttyent.h>
#include <unistd.h>
#include <paths.h>
#include <util.h>
#include <libgen.h>
#include <paths.h>
#include <termios.h>

#include "launchd.h"
#include "launchd_runtime.h"

#define _PATH_RUNCOM            "/etc/rc"

#define	STALL_TIMEOUT		30	/* wait N secs after warning */

static void stall(char *, ...);

static void single_user_callback(void *, struct kevent *);
static kq_callback kqsingle_user_callback = single_user_callback;
static void runcom_callback(void *, struct kevent *);
static kq_callback kqruncom_callback = runcom_callback;

static void single_user(void);
static void runcom(void);

static bool single_user_mode = false;
static bool run_runcom = true;
static pid_t single_user_pid = 0;
static pid_t runcom_pid = 0;

static void setctty(const char *, int);

static void setsecuritylevel(int);
static int getsecuritylevel(void);
static bool should_fsck(void);

void
init_boot(bool sflag)
{
	if (sflag) {
		single_user_mode = true;
		run_runcom = false;
	}
}

void
init_pre_kevent(void)
{
	if (single_user_pid || runcom_pid)
		return;

	if (single_user_mode)
		return single_user();

	if (run_runcom)
		return runcom();
		
	/*
	 * If the administrator has not set the security level to -1
	 * to indicate that the kernel should not run multiuser in secure
	 * mode, and the run script has not set a higher level of security 
	 * than level 1, then put the kernel into secure mode.
	 */
	if (getsecuritylevel() == 0) {
		setsecuritylevel(1);
	}
}

void
stall(char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_ALERT, message, ap);
	va_end(ap);
	sleep(STALL_TIMEOUT);
}

int
getsecuritylevel(void)
{
	int name[2], curlevel;
	size_t len;

	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	len = sizeof (curlevel);
	if (sysctl(name, 2, &curlevel, &len, NULL, 0) == -1) {
		syslog(LOG_ALERT, "cannot get kernel security level: %m");
		return -1;
	}
	return curlevel;
}

void
setsecuritylevel(int newlevel)
{
	int name[2], curlevel;

	curlevel = getsecuritylevel();
	if (newlevel == curlevel)
		return;
	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	if (sysctl(name, 2, NULL, NULL, &newlevel, sizeof newlevel) == -1) {
		syslog(LOG_ALERT, "cannot change kernel security level from %d to %d: %m",
				curlevel, newlevel);
		return;
	}
	syslog(LOG_INFO, "kernel security level changed from %d to %d",
	    curlevel, newlevel);
}

/*
 * Start a session and allocate a controlling terminal.
 * Only called by children of init after forking.
 */
void
setctty(const char *name, int flags)
{
	int fd;

	revoke(name);
	if ((fd = open(name, flags | O_RDWR)) == -1) {
		stall("can't open %s: %m", name);
		exit(EXIT_FAILURE);
	}
	if (login_tty(fd) == -1) {
		stall("can't get %s for controlling terminal: %m", name);
		exit(EXIT_FAILURE);
	}
}

void
single_user(void)
{
	bool runcom_fsck = should_fsck();
	char *argv[2];

	if (getsecuritylevel() > 0)
		setsecuritylevel(0);

	if ((single_user_pid = launchd_fork()) == -1) {
		syslog(LOG_ERR, "can't fork single-user shell, trying again: %m");
		return;
	} else if (single_user_pid == 0) {
		setctty(_PATH_CONSOLE, O_POPUP);

                setenv("TERM", "vt100", 1);

		if (runcom_fsck) {
			fprintf(stdout, "Singleuser boot -- fsck not done\n");
			fprintf(stdout, "Root device is mounted read-only\n\n");
			fprintf(stdout, "If you want to make modifications to files:\n");
			fprintf(stdout, "\t/sbin/fsck -fy\n\t/sbin/mount -uw /\n\n");
			fprintf(stdout, "If you wish to boot the system:\n");
			fprintf(stdout, "\texit\n\n");
			fflush(stdout);
		}

		argv[0] = "-sh";
		argv[1] = NULL;
		execv(_PATH_BSHELL, argv);
		syslog(LOG_ERR, "can't exec %s for single user: %m", _PATH_BSHELL);
		sleep(STALL_TIMEOUT);
		exit(EXIT_FAILURE);
	} else {
		if (kevent_mod(single_user_pid, EVFILT_PROC, EV_ADD, 
					NOTE_EXIT, 0, &kqsingle_user_callback) == -1)
			single_user_callback(NULL, NULL);
	}
}

void
single_user_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	int status;

	if (!launchd_assumes(waitpid(single_user_pid, &status, 0) == single_user_pid))
		return;

	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
		syslog(LOG_INFO, "single user shell terminated, restarting");
		run_runcom = true;
		single_user_mode = false;
	} else {
		syslog(LOG_INFO, "single user shell terminated.");
		run_runcom = false;
		if (WTERMSIG(status) != SIGKILL)
			single_user_mode = true;
	}

	single_user_pid = 0;
}

static struct timeval runcom_start_tv = { 0, 0 };

/*
 * Run the system startup script.
 */
void
runcom(void)
{
	char *argv[] = { "/bin/launchctl", "bootstrap", NULL };
	struct termios term;
	int vdisable;

	gettimeofday(&runcom_start_tv, NULL);

	if ((runcom_pid = launchd_fork()) == -1) {
		syslog(LOG_ERR, "can't fork for %s on %s: %m", _PATH_BSHELL, _PATH_RUNCOM);
		sleep(STALL_TIMEOUT);
		runcom_pid = 0;
		single_user_mode = true;
		return;
	} else if (runcom_pid > 0) {
		run_runcom = false;
		if (kevent_mod(runcom_pid, EVFILT_PROC, EV_ADD, 
					NOTE_EXIT, 0, &kqruncom_callback) == -1) {
			runcom_callback(NULL, NULL);
		}
		return;
	}

	setctty(_PATH_CONSOLE, 0);

	if ((vdisable = fpathconf(STDIN_FILENO, _PC_VDISABLE)) == -1) {
		syslog(LOG_WARNING, "fpathconf(\"%s\") %m", _PATH_CONSOLE);
	} else if (tcgetattr(STDIN_FILENO, &term) == -1) {
		syslog(LOG_WARNING, "tcgetattr(\"%s\") %m", _PATH_CONSOLE);
	} else {
		term.c_cc[VINTR] = vdisable;
		term.c_cc[VKILL] = vdisable;
		term.c_cc[VQUIT] = vdisable;
		term.c_cc[VSUSP] = vdisable;
		term.c_cc[VSTART] = vdisable;
		term.c_cc[VSTOP] = vdisable;
		term.c_cc[VDSUSP] = vdisable;

		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
			syslog(LOG_WARNING, "tcsetattr(\"%s\") %m", _PATH_CONSOLE);
	}

	execv(argv[0], argv);
	stall("can't exec %s for %s: %m", _PATH_BSHELL, _PATH_RUNCOM);
	exit(EXIT_FAILURE);
}

void
runcom_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	int status;
	struct timeval runcom_end_tv, runcom_total_tv;
	double sec;

	gettimeofday(&runcom_end_tv, NULL);
	timersub(&runcom_end_tv, &runcom_start_tv, &runcom_total_tv);
	sec = runcom_total_tv.tv_sec;
	sec += (double)runcom_total_tv.tv_usec / (double)1000000;
	syslog(LOG_INFO, "%s finished in: %.3f seconds", _PATH_RUNCOM, sec);

	if (launchd_assumes(waitpid(runcom_pid, &status, 0) == runcom_pid)) {
		runcom_pid = 0;
	} else {
		syslog(LOG_ERR, "going to single user mode");
		single_user_mode = true;
		return;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
		return;
	} else if (WIFSIGNALED(status) && (WTERMSIG(status) == SIGTERM || WTERMSIG(status) == SIGKILL)) {
		return;
	}

	syslog(LOG_ERR, "%s on %s terminated abnormally, going to single user mode",
			_PATH_BSHELL, _PATH_RUNCOM);
	single_user_mode = true;
}

bool
init_check_pid(pid_t p)
{
	if (single_user_pid == p)
		return true;

	if (runcom_pid == p)
		return true;

	return false;
}

bool
should_fsck(void)
{
	struct statfs sfs;
	bool r = true;

	if (launchd_assumes(statfs("/", &sfs) != -1)) {
		if (!(sfs.f_flags & MNT_RDONLY)) {
			r = false;
		}
	}
	
	return r;
}
