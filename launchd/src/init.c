/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

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
#include <pwd.h>
#include <paths.h>

#include "launchd.h"

#define _PATH_RUNCOM            "/etc/rc"
#define _PATH_RUNCOM_BOOT       _PATH_RUNCOM ".boot"

/*
 * Sleep times; used to prevent thrashing.
 */
#define	GETTY_SPACING		 5	/* N secs minimum getty spacing */
#define	GETTY_SLEEP		30	/* sleep N secs after spacing problem */
#define	STALL_TIMEOUT		30	/* wait N secs after warning */
#define	DEATH_WATCH		10	/* wait N secs for procs to die */
#define FAILED_HW_PASS		 5	/* wait N secs before croaking user */

static void stall(char *, ...);

static void single_user_callback(void *, struct kevent *);
static kq_callback kqsingle_user_callback = single_user_callback;
static void runcom_callback(void *, struct kevent *);
static kq_callback kqruncom_callback = runcom_callback;

static void single_user(void);
static void runcom(void);

static bool runcom_boot = true;		/* Run the rc.boot script */
static bool runcom_verbose = false;
static bool runcom_safe = false;
static bool single_user_mode = false;
static bool run_runcom = true;
static pid_t single_user_pid = 0;
static pid_t runcom_pid = 0;

static void setctty(const char *, int);

// gvdl@next.com 14 Aug 1995
//   - from ~apps/loginwindow_proj/loginwindow/common.h
#define REALLY_EXIT_TO_CONSOLE                  229

// From old init.c
// These flags are used in the se_flags field of the init_session structure
#define	SE_SHUTDOWN	0x1		/* session won't be restarted */

// The flags below control what sort of getty is launched.
#define SE_GETTY_LAUNCH	0x30	/* What type of getty to launch */ 
#define SE_COMMON	0x00	/* Usual command that is run - getty */
#define SE_ONERROR	0x10	/* Command to run if error condition occurs.
				 * This will almost always be the windowserver
				 * and loginwindow.  This is so if the w.s.
				 * ever dies, that the naive user (stan)
				 * doesn't ever see the console window. */
#define SE_ONOPTION 	0x20	/* Command to run when loginwindow exits with
				 * special error code (229).  This signifies
				 * that the user typed "console" at l.w. and
				 * l.w. wants to exit and have init run getty
				 * which will then put up a console window. */

typedef struct _se_command {
	char	*path;		/* what to run on that port */
	char	**argv;		/* pre-parsed argument array */
} se_cmd_t;

typedef struct init_session {
	kq_callback se_callback;	/* run loop callback */
	int	se_index;		/* index of entry in ttys file */
	pid_t	se_process;		/* controlling process */
	time_t	se_started;		/* used to avoid thrashing */
	int	se_flags;		/* status of session */
	char	*se_device;		/* filename of port */
	int	se_wstatus;		/* wait status results */
	se_cmd_t se_getty;		/* what to run on that port */
	se_cmd_t se_onerror;		/* See SE_ONERROR above */
	se_cmd_t se_onoption;		/* See SE_ONOPTION above */
	TAILQ_ENTRY(init_session) tqe;
} *session_t;

static TAILQ_HEAD(sessionshead, init_session) sessions = TAILQ_HEAD_INITIALIZER(sessions);

static void session_new(int, struct ttyent *);
static void session_free(session_t);
static void session_launch(session_t);
static void session_reap(session_t);
static void session_callback(void *, struct kevent *);

static char **construct_argv(char *);
static void setsecuritylevel(int);
static int getsecuritylevel(void);
static int setupargv(session_t, struct ttyent *);


static int fwexecv(int *status, const char *path, char * const *argv)
{
	pid_t p = fork();

	if (p == -1) {
		return -1;
	} else if (p == 0) {
		setctty(_PATH_CONSOLE, 0);
		execv(path, argv);
		exit(EXIT_FAILURE);
	}

	return waitpid(p, status, 0);
}

void
init_boot(bool sflag, bool vflag, bool xflag, bool bflag)
{
	int status;
	char *argv[5];

	if (sflag) {
		single_user_mode = true;
		run_runcom = false;
	}
	if (bflag)
		runcom_boot = false;
	if (vflag)
		runcom_verbose = true;
	if (xflag)
		runcom_safe = true;

	argv[0] = "sh";
	argv[1] = _PATH_RUNCOM_BOOT;
	argv[2] = NULL;
	argv[3] = NULL;
	argv[4] = NULL;

	if (xflag && sflag) {
		argv[2] = "-x";
		argv[3] = "-s";
	} else if (xflag) {
		argv[2] = "-x";
	} else if (sflag) {
		argv[2] = "-s";
	}

	if (!(fwexecv(&status, _PATH_BSHELL, argv) > 0 &&
				WIFEXITED(status) && WEXITSTATUS(status) == 0))
		single_user_mode = true;
}

void
init_pre_kevent(void)
{
	session_t s;

	if (single_user_mode && single_user_pid == 0)
		single_user();

	if (run_runcom)
		runcom();
		
	if (!single_user_mode && !run_runcom && runcom_pid == 0) {
		/*
		 * If the administrator has not set the security level to -1
		 * to indicate that the kernel should not run multiuser in secure
		 * mode, and the run script has not set a higher level of security 
		 * than level 1, then put the kernel into secure mode.
		 */
		if (getsecuritylevel() == 0)
			setsecuritylevel(1);

		TAILQ_FOREACH(s, &sessions, tqe) {
			if (s->se_process == 0)
				session_launch(s);
		}
	}
}

static void
stall(char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_ALERT, message, ap);
	va_end(ap);
	sleep(STALL_TIMEOUT);
}

static int
getsecuritylevel(void)
{
	int name[2], curlevel;
	size_t len;
	extern int errno;

	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	len = sizeof (curlevel);
	if (sysctl(name, 2, &curlevel, &len, NULL, 0) == -1) {
		syslog(LOG_ALERT, "cannot get kernel security level: %m");
		return -1;
	}
	return curlevel;
}

static void
setsecuritylevel(int newlevel)
{
	int name[2], curlevel;
	extern int errno;

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
static void
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

static void
do_security_check(void)
{
	struct ttyent *typ;
	struct passwd *pp;
	static const char banner[] = "Enter root password, or ^D to go multi-user\n";
	char *clear, *password;

	/*
	 * Check the root password.
	 * We don't care if the console is 'on' by default;
	 * it's the only tty that can be 'off' and 'secure'.
	 */
	typ = getttynam("console");
	pp = getpwnam("root");
	if (typ && (typ->ty_status & TTY_SECURE) == 0 && pp) {
		write(STDERR_FILENO, banner, sizeof(banner) - 1);
		for (;;) {
			clear = getpass("Password:");
			if (clear == 0 || *clear == '\0')
				exit(EXIT_SUCCESS);
			password = crypt(clear, pp->pw_passwd);
			memset(clear, 0, _PASSWORD_LEN);
			if (strcmp(password, pp->pw_passwd) == 0)
				break;
			syslog(LOG_NOTICE, "single-user login failed");
		}
	}
	endttyent();
	endpwent();
}

static void
single_user(void)
{
	char *argv[2];

	if (getsecuritylevel() > 0)
		setsecuritylevel(0);

	if ((single_user_pid = fork()) == -1) {
		syslog(LOG_ERR, "can't fork single-user shell, trying again: %m");
		return;
	} else if (single_user_pid == 0) {
		setctty(_PATH_CONSOLE, O_POPUP);

		do_security_check();

                setenv("PATH", _PATH_STDPATH, 1);

                setenv("TERM", "vt100", 1);

		argv[0] = "-sh";
		argv[1] = 0;
		execv(_PATH_BSHELL, argv);
		syslog(LOG_ERR, "can't exec %s for single user: %m", _PATH_BSHELL);
		sleep(STALL_TIMEOUT);
		exit(EXIT_FAILURE);
	} else {
		if (__kevent(single_user_pid, EVFILT_PROC, EV_ADD, 
					NOTE_EXIT, 0, &kqsingle_user_callback) == -1)
			single_user_callback(NULL, NULL);
	}
}

static void
single_user_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	int status;

	switch (waitpid(single_user_pid, &status, 0)) {
	case -1:
		syslog(LOG_ERR, "single_user_callback(): waitpid(): %m");
		return;
	case 0:
		syslog(LOG_ERR, "single_user_callback(): waitpid() returned 0");
		return;
	default:
		break;
	}

	if (!WIFEXITED(status)) {
		if (WTERMSIG(status) == SIGKILL) { 
			/* 
			 *  reboot(8) killed shell? 
			 */
			syslog(LOG_INFO, "single user shell terminated.");
			sleep(STALL_TIMEOUT);
			exit(EXIT_SUCCESS);
		} else {	
			syslog(LOG_INFO, "single user shell terminated, restarting");
			return;
		}
	}

	single_user_pid = 0;
	single_user_mode = false;
	run_runcom = true;
}

/*
 * Run the system startup script.
 */
static void
runcom(void)
{
	char *argv[4];
	char options[4];

	if ((runcom_pid = fork()) == -1) {
		syslog(LOG_ERR, "can't fork for %s on %s: %m", _PATH_BSHELL, _PATH_RUNCOM);
		sleep(STALL_TIMEOUT);
		runcom_pid = 0;
		single_user_mode = true;
		return;
	} else if (runcom_pid > 0) {
		run_runcom = false;
		if (__kevent(runcom_pid, EVFILT_PROC, EV_ADD, 
					NOTE_EXIT, 0, &kqruncom_callback) == -1) {
			runcom_callback(NULL, NULL);
		}
		return;
	}

	signal(SIGTSTP, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	setctty(_PATH_CONSOLE, 0);

	argv[0] = "sh";
	argv[1] = _PATH_RUNCOM;
	argv[2] = NULL;
	argv[3] = NULL;

	if (runcom_verbose || runcom_safe) {
		int i = 0;

		options[i++] = '-';
		if (runcom_verbose) options[i++] = 'v';
		if (runcom_safe   ) options[i++] = 'x';
		options[i] = '\0';

		argv[2] = options;
	}

	execv(_PATH_BSHELL, argv);
	stall("can't exec %s for %s: %m", _PATH_BSHELL, _PATH_RUNCOM);
	exit(EXIT_FAILURE);
}

static void
runcom_callback(void *obj __attribute__((unused)), struct kevent *kev __attribute__((unused)))
{
	int status;

	switch (waitpid(runcom_pid, &status, 0)) {
	case -1:
	case 0:
		syslog(LOG_ERR, "wait for %s on %s failed: %m; going to single user mode",
			_PATH_BSHELL, _PATH_RUNCOM);
		single_user_mode = true;
		return;
	default:
		runcom_pid = 0;
		break;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
		logwtmp("~", "reboot", "");
		update_ttys();
		return;
	} else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM) {
		/* /etc/rc executed /sbin/reboot; wait for the end quietly */
		for (;;)
			pause();
	}

	syslog(LOG_ERR, "%s on %s terminated abnormally, going to single user mode",
			_PATH_BSHELL, _PATH_RUNCOM);
	single_user_mode = true;
}

/*
 * Construct an argument vector from a command line.
 */
char **
construct_argv(command)
	char *command;
{
	int argc = 0;
	char **argv = (char **) malloc(((strlen(command) + 1) / 2 + 1)
						* sizeof (char *));
	static const char separators[] = " \t";

	if ((argv[argc++] = strtok(command, separators)) == 0)
		return 0;
	while ((argv[argc++] = strtok(NULL, separators)))
		continue;
	return argv;
}

/*
 * Deallocate a session descriptor.
 */

static void free_command(se_cmd_t *se_cmd)
{
    if (se_cmd->path) {
	free(se_cmd->path);
	free(se_cmd->argv);
    }
}

void
session_free(session_t s)
{
	TAILQ_REMOVE(&sessions, s, tqe);
	if (s->se_process) {
		if (__kevent(s->se_process, EVFILT_PROC, EV_ADD, 
					NOTE_EXIT, 0, &kqsimple_zombie_reaper) == -1)
			session_reap(s);
		else
			kill(s->se_process, SIGHUP);
	}
	free(s->se_device);
	free_command(&s->se_getty);
	free_command(&s->se_onerror);
	free_command(&s->se_onoption);
	free(s);
}

static int setup_command(se_cmd_t *se_cmd, char *command, char *arg )
{
	char *commandWithArg;

	asprintf(&commandWithArg, "%s %s", command, arg);

	free_command(se_cmd);

	se_cmd->path = commandWithArg;
	se_cmd->argv = construct_argv(commandWithArg);
	if (se_cmd->argv == NULL) {
		free(se_cmd->path);
		se_cmd->path = NULL;
		return 0;
	}
	return 1;
}

/*
 * Calculate getty and if useful window argv vectors.
 */
static int
setupargv(sp, typ)
	session_t sp;
	struct ttyent *typ;
{
    char *type;

    if ( !setup_command(&sp->se_getty, typ->ty_getty, typ->ty_name) )
    {
	type = "getty";
	goto bad_args;
    }

    if (typ->ty_onerror
    && !setup_command(&sp->se_onerror, typ->ty_onerror, typ->ty_name) )
    {
	type = "onerror";
	goto bad_args;
    }

    if (typ->ty_onoption
    && !setup_command(&sp->se_onoption, typ->ty_onoption, typ->ty_name) )
    {
	type = "onoption";
	goto bad_args;
    }

    return 1;

bad_args:
    syslog(LOG_WARNING, "can't parse %s for port %s", type, sp->se_device);
    return 0;
}


/*
 * Allocate a new session descriptor.
 */
void
session_new(session_index, typ)
	int session_index;
	struct ttyent *typ;
{
	session_t s;

	if ((typ->ty_status & TTY_ON) == 0 ||
	    typ->ty_name == 0 ||
	    typ->ty_getty == 0)
		return;

	s = calloc(1, sizeof(struct init_session));

	s->se_callback = session_callback;
	s->se_index = session_index;

	TAILQ_INSERT_TAIL(&sessions, s, tqe);

	asprintf(&s->se_device, "%s%s", _PATH_DEV, typ->ty_name);

	if (setupargv(s, typ) == 0)
		session_free(s);
}

static void
session_launch(session_t s)
{
	pid_t pid;
	sigset_t mask;
	se_cmd_t *se_cmd;
	const char *session_type = NULL;
	time_t current_time      = time(NULL);

	// Setup the default values;
	switch (s->se_flags & SE_GETTY_LAUNCH) {
	case SE_ONOPTION:
		if (s->se_onoption.path) {
			se_cmd       = &s->se_onoption;
			session_type = "onoption";
			break;
		}
		/* No break */
	case SE_ONERROR:
		if (s->se_onerror.path) {
			se_cmd       = &s->se_onerror;
			session_type = "onerror";
			break;
		}
		/* No break */
	case SE_COMMON:
	default:
		se_cmd       = &s->se_getty;
		session_type = "getty";
		break;
	}

	/* fork(), not vfork() -- we can't afford to block. */
	if ((pid = fork()) == -1) {
		syslog(LOG_ERR, "can't fork for %s on port %s: %m",
				session_type, s->se_device);
		update_ttys();
		return;
	}

	if (pid) {
		s->se_process = pid;
		s->se_started = time(NULL);
		s->se_flags  &= ~SE_GETTY_LAUNCH; // clear down getty launch type
		if (__kevent(pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &s->se_callback) == -1)
			session_reap(s);
		return;
	}

	if (current_time > s->se_started &&
	    current_time - s->se_started < GETTY_SPACING) {
		syslog(LOG_WARNING, "%s repeating too quickly on port %s, sleeping",
		        session_type, s->se_device);
		sleep(GETTY_SLEEP);
	}

	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	execv(se_cmd->argv[0], se_cmd->argv);
	stall("can't exec %s '%s' for port %s: %m", session_type,
		se_cmd->argv[0], s->se_device);
	exit(EXIT_FAILURE);
}

static void
session_callback(void *obj, struct kevent *kev __attribute__((unused)))
{
	session_t s = obj;

	session_reap(s);
	if (s->se_flags & SE_SHUTDOWN) {
		session_free(s);
	} else {
		session_launch(s);
	}
}

static void
session_reap(session_t s)
{
	char *line;
	pid_t pr = s->se_process;

	if (s->se_wstatus == 0)
		pr = waitpid(s->se_process, &s->se_wstatus, 0);

	switch (pr) {
	case -1:
		syslog(LOG_DEBUG, "waitpid(): %m");
		return;
	case 0:
		syslog(LOG_DEBUG, "waitpid() == 0");
		return;
	default:
		if (WIFSIGNALED(s->se_wstatus)) {
			s->se_flags |= SE_ONERROR; 
		} else if (WEXITSTATUS(s->se_wstatus) == REALLY_EXIT_TO_CONSOLE) {
			/* WIFEXITED(s->se_wstatus) assumed */
			s->se_flags |= SE_ONOPTION;
		} else {
			s->se_flags |= SE_ONERROR;
		}       
		s->se_wstatus = 0;
		s->se_process = 0;
		line = s->se_device + sizeof(_PATH_DEV) - 1;
		if (logout(line))
			logwtmp(line, "", "");
		break;
	}
}

/*
 * This is an n-squared algorithm.  We hope it isn't run often...
 */
void
update_ttys(void)
{
	session_t sp;
	struct ttyent *typ;
	int session_index = 0;
	int devlen;

	devlen = sizeof(_PATH_DEV) - 1;
	while ((typ = getttyent())) {
		++session_index;

		TAILQ_FOREACH(sp, &sessions, tqe) {
			if (strcmp(typ->ty_name, sp->se_device + devlen) == 0)
				break;
		}

		if (sp == NULL) {
			session_new(session_index, typ);
			continue;
		}

		if (sp->se_index != session_index) {
			syslog(LOG_INFO, "port %s changed utmp index from %d to %d",
			       sp->se_device, sp->se_index,
			       session_index);
			sp->se_index = session_index;
		}

		if ((typ->ty_status & TTY_ON) == 0 ||
		    typ->ty_getty == 0) {
			session_free(sp);
			continue;
		}

		sp->se_flags &= ~SE_SHUTDOWN;

		if (setupargv(sp, typ) == 0) {
			syslog(LOG_WARNING, "can't parse getty for port %s",
				sp->se_device);
			session_free(sp);
		}
	}

	endttyent();
}

/*
 * Block further logins.
 */
void
catatonia(void)
{
	session_t s;

	TAILQ_FOREACH(s, &sessions, tqe)
		s->se_flags |= SE_SHUTDOWN;
}

/*
 * Bring the system down to single user.
 */
void
death(void)
{
	int i;
	static const int death_sigs[3] = { SIGHUP, SIGTERM, SIGKILL };

	catatonia();

	single_user_mode = true;

	/* NB: should send a message to the session logger to avoid blocking. */
	logwtmp("~", "shutdown", "");

	for (i = 0; i < 3; ++i) {
		if (kill(-1, death_sigs[i]) == -1 && errno == ESRCH)
			return;
		syslog(LOG_ERR, "we should be trying to detect a valid clean-up");
		sleep(DEATH_WATCH);
	}

	syslog(LOG_WARNING, "some processes would not die; ps axl advised");
}

bool init_check_pid(pid_t p, int status)
{
	struct kevent kev;
	session_t s;

	TAILQ_FOREACH(s, &sessions, tqe) {
		if (s->se_process == p) {
			s->se_wstatus = status;
			return true;
		}
	}
	if (single_user_pid == p)
		return true;
	if (runcom_pid == p)
		return true;
	return false;
}
