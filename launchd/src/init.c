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

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <db.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ttyent.h>
#include <unistd.h>
#include <paths.h>

#include <stdarg.h>

#ifdef SECURE
#include <pwd.h>
#endif

#include "pathnames.h"

/*
 * Until the mythical util.h arrives...
 */
extern int login_tty __P((int));
extern int logout __P((const char *));
extern void logwtmp __P((const char *, const char *, const char *));

/*
 * Sleep times; used to prevent thrashing.
 */
#define	GETTY_SPACING		 5	/* N secs minimum getty spacing */
#define	GETTY_SLEEP		30	/* sleep N secs after spacing problem */
#define	WINDOW_WAIT		 3	/* wait N secs after starting window */
#define	STALL_TIMEOUT		30	/* wait N secs after warning */
#define	DEATH_WATCH		10	/* wait N secs for procs to die */
#define FAILED_HW_PASS		 5	/* wait N secs before croaking user */

void handle __P((sig_t, ...));
void delset __P((sigset_t *, ...));

void stall __P((char *, ...));
void warning __P((char *, ...));
void emergency __P((char *, ...));
void disaster __P((int));
void badsys __P((int));

/*
 * We really need a recursive typedef...
 * The following at least guarantees that the return type of (*state_t)()
 * is sufficiently wide to hold a function pointer.
 */
typedef long (*state_func_t) __P((void));
typedef state_func_t (*state_t) __P((void));

state_func_t single_user __P((void));
state_func_t runcom __P((void));
state_func_t read_ttys __P((void));
state_func_t multi_user __P((void));
state_func_t clean_ttys __P((void));
state_func_t catatonia __P((void));
state_func_t death __P((void));

enum { AUTOBOOT, FASTBOOT, BOOT_SCRIPT } runcom_mode = AUTOBOOT;
int runcom_boot = 1;	/* Run the rc.boot script */
int runcom_verbose = 0;
int runcom_safe = 0;

void transition __P((state_t));
state_t requested_transition = runcom;

void setctty __P((char *, int));


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
	int	se_index;		/* index of entry in ttys file */
	pid_t	se_process;		/* controlling process */
	time_t	se_started;		/* used to avoid thrashing */
	int	se_flags;		/* status of session */
	char	*se_device;		/* filename of port */
	se_cmd_t se_getty;		/* what to run on that port */
	se_cmd_t se_window;		/* window system (started only once) */
	se_cmd_t se_onerror;		/* See SE_ONERROR above */
	se_cmd_t se_onoption;		/* See SE_ONOPTION above */
	struct	init_session *se_prev;
	struct	init_session *se_next;
} session_t;

void free_session __P((session_t *));
session_t *new_session __P((session_t *, int, struct ttyent *));
session_t *sessions;

char **construct_argv __P((char *));
void collect_child __P((pid_t));
pid_t start_getty __P((session_t *));
void transition_handler __P((int));
void alrm_handler __P((int));
void setsecuritylevel __P((int));
int getsecuritylevel __P((void));
int setupargv __P((session_t *, struct ttyent *));
int clang;

void clear_session_logs __P((session_t *));

int start_session_db __P((void));
void add_session __P((session_t *));
void del_session __P((session_t *));
session_t *find_session __P((pid_t));
DB *session_db;

/*
 * The mother of all processes.
 */
int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	struct sigaction sa;
	sigset_t mask;


	/* Dispose of random users. */
	if (getuid() != 0) {
		(void)fprintf(stderr, "init: %s\n", strerror(EPERM));
		exit (1);
	}

	/* System V users like to reexec init. */
	if (getpid() != 1) {
		(void)fprintf(stderr, "init: already running\n");
		exit (1);
	}

	/*
	 * Note that this does NOT open a file...
	 * Does 'init' deserve its own facility number?
	 */
	openlog("init", LOG_CONS|LOG_ODELAY, LOG_AUTH);

	/*
	 * Create an initial session.
	 */
	if (setsid() < 0)
		warning("initial setsid() failed: %m");

	/*
	 * Establish an initial user so that programs running
	 * single user do not freak out and die (like passwd).
	 */
	if (setlogin("root") < 0)
		warning("setlogin() failed: %m");

	/*
	 * This code assumes that we always get arguments through flags,
	 * never through bits set in some random machine register.
	 */

#ifdef DEBUG
	{
	    int i;
	    for (i = 0; i <= argc; i++) {
		if (argv[i])
		    warning("init argument %d: '%s'", i, argv[i]);
		else
		    warning("init argument %d: ***NULL***", i);
	    }
	}
#endif

	while ((c = getopt(argc, argv, "sfbvx")) != -1) {
#ifdef DEBUG
		warning("handling init argument '-%c'", c);
#endif
		switch (c) {
		case 's':
			requested_transition = single_user;
			break;
		case 'f':
			runcom_mode = FASTBOOT;
			break;
		case 'b':
			runcom_boot = 0;	// Don't runcom rc.boot
			break;
		case 'v':
			runcom_verbose = 1;
			break;
		case 'x':
			runcom_safe = 1;
			break;
		default:
			warning("unrecognized flag '-%c'", c);
			break;
		}
	}

	if (optind != argc)
		warning("ignoring excess arguments");

	/*
	 * We catch or block signals rather than ignore them,
	 * so that they get reset on exec.
	 */
	handle(badsys, SIGSYS, 0);
	handle(disaster, SIGABRT, SIGFPE, SIGILL, SIGSEGV,
	       SIGBUS, SIGXCPU, SIGXFSZ, 0);
	handle(transition_handler, SIGHUP, SIGTERM, SIGTSTP, 0);
	handle(alrm_handler, SIGALRM, 0);
	sigfillset(&mask);
	delset(&mask, SIGABRT, SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGSYS,
		SIGXCPU, SIGXFSZ, SIGHUP, SIGTERM, SIGTSTP, SIGALRM, 0);
	sigprocmask(SIG_SETMASK, &mask, (sigset_t *) 0);
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;
	(void) sigaction(SIGTTIN, &sa, (struct sigaction *)0);
	(void) sigaction(SIGTTOU, &sa, (struct sigaction *)0);

	/*
	 * Paranoia.
	 */
	close(0);
	close(1);
	close(2);

	if (runcom_boot)
	{
	    int old_rc_mode = runcom_mode;

	    runcom_mode = BOOT_SCRIPT;
	    if (runcom() == (state_func_t) single_user)
		requested_transition = single_user; // Error in script
	    runcom_mode = old_rc_mode;
	}

	/*
	 * Start the state machine.
	 */
	transition(requested_transition);

	/*
	 * Should never reach here.
	 */
	return 1;
}

/*
 * Associate a function with a signal handler.
 */
void
handle(sig_t handler, ...)
{
	int sig;
	struct sigaction sa;
	int mask_everything;
	va_list ap;
	va_start(ap, handler);

	sa.sa_handler = handler;
	sigfillset(&mask_everything);

	while ((sig = va_arg(ap, int)) != 0) {
		sa.sa_mask = mask_everything;
		/* XXX SA_RESTART? */
		sa.sa_flags = sig == SIGCHLD ? SA_NOCLDSTOP : 0;
		sigaction(sig, &sa, (struct sigaction *) 0);
	}
	va_end(ap);
}

/*
 * Delete a set of signals from a mask.
 */
void
delset(sigset_t *maskp, ...)
{
	int sig;
	va_list ap;
	va_start(ap, maskp);

	while ((sig = va_arg(ap, int)) != 0)
		sigdelset(maskp, sig);
	va_end(ap);
}

/*
 * Log a message and sleep for a while (to give someone an opportunity
 * to read it and to save log or hardcopy output if the problem is chronic).
 * NB: should send a message to the session logger to avoid blocking.
 */
void
stall(char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_ALERT, message, ap);
	va_end(ap);
	sleep(STALL_TIMEOUT);
}

/*
 * Like stall(), but doesn't sleep.
 * If cpp had variadic macros, the two functions could be #defines for another.
 * NB: should send a message to the session logger to avoid blocking.
 */
void
warning(char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_ALERT, message, ap);
	va_end(ap);
}

/*
 * Log an emergency message.
 * NB: should send a message to the session logger to avoid blocking.
 */
void
emergency(char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_EMERG, message, ap);
	va_end(ap);
}

/*
 * Catch a SIGSYS signal.
 *
 * These may arise if a system does not support sysctl.
 * We tolerate up to 25 of these, then throw in the towel.
 */
void
badsys(sig)
	int sig;
{
	static int badcount = 0;

	if (badcount++ < 25)
		return;
	disaster(sig);
}

/*
 * Catch an unexpected signal.
 */
void
disaster(sig)
	int sig;
{
	emergency("fatal signal: %s",
		sig < NSIG ? sys_siglist[sig] : "unknown signal");

	sleep(STALL_TIMEOUT);
	_exit(sig);		/* reboot */
}

/*
 * Get the security level of the kernel.
 */
int
getsecuritylevel()
{
#ifdef KERN_SECURELVL
	int name[2], curlevel;
	size_t len;
	extern int errno;

	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	len = sizeof curlevel;
	if (sysctl(name, 2, &curlevel, &len, NULL, 0) == -1) {
		emergency("cannot get kernel security level: %s",
		    strerror(errno));
		return (-1);
	}
	return (curlevel);
#else
	return (-1);
#endif
}

/*
 * Set the security level of the kernel.
 */
void
setsecuritylevel(newlevel)
	int newlevel;
{
#ifdef KERN_SECURELVL
	int name[2], curlevel;
	extern int errno;

	curlevel = getsecuritylevel();
	if (newlevel == curlevel)
		return;
	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	if (sysctl(name, 2, NULL, NULL, &newlevel, sizeof newlevel) == -1) {
		emergency(
		    "cannot change kernel security level from %d to %d: %s",
		    curlevel, newlevel, strerror(errno));
		return;
	}
#ifdef SECURE
	warning("kernel security level changed from %d to %d",
	    curlevel, newlevel);
#endif
#endif
}

/*
 * Change states in the finite state machine.
 * The initial state is passed as an argument.
 */
void
transition(s)
	state_t s;
{
	for (;;)
		s = (state_t) (*s)();
}

/*
 * Close out the accounting files for a login session.
 * NB: should send a message to the session logger to avoid blocking.
 */
void
clear_session_logs(sp)
	session_t *sp;
{
	char *line = sp->se_device + sizeof(_PATH_DEV) - 1;

	if (logout(line))
		logwtmp(line, "", "");
}

/*
 * Start a session and allocate a controlling terminal.
 * Only called by children of init after forking.
 */
void
setctty(name, flags)
	char *name;
	int flags;
{
	int fd;

	(void) revoke(name);
	if ((fd = open(name, flags | O_RDWR)) == -1) {
		stall("can't open %s: %m", name);
		_exit(1);
	}
	if (login_tty(fd) == -1) {
		stall("can't get %s for controlling terminal: %m", name);
		_exit(1);
	}
}

#if m68k
/*
 * Taken from etc/halt/halt.c
 */

#include <stdio.h>
#include <signal.h>
#include <sgtty.h>

static void shutend(void)
{
	register i;

	acct(0);
	for (i = 0; i < 10; i++)
		close(i);

	logwtmp("~", "shutdown", "");
}

static void do_halt(void)
{
	char sbuf [40];
	int halthowto = RB_HALT;

	(void) kill(-1, SIGTERM);	/* one chance to catch it */

	sprintf (sbuf, "Invalid hardware password, halting machine...\n");
	write (1, sbuf, strlen (sbuf));

	signal(SIGALRM, SIG_DFL);
	shutend();
	sync();

	signal(SIGALRM, alrm_handler);
	alarm(FAILED_HW_PASS);
	pause();

	syscall(SYS_reboot, halthowto);
}

/*
 * Taken from lib/gen/getpass.c
 */

static char *gethwpasswd(char *prompt)
{
    struct termios term;
    register char *p;
    register c;
    static char pbuf[9];
    int echo;

    (void) tcgetattr(1, &term);
    if (echo = (term.c_lflag & ECHO))
    {
	term.c_lflag &= ~ECHO;
	(void) tcsetattr(1, TCSAFLUSH|TCSASOFT, &term);
    }

    write(2, prompt, strlen(prompt));

    for (p = pbuf; (c = getchar()) != '\n' && c != EOF; )
	if (p < &pbuf[8])
	    *p++ = c;
    *p = '\0';

    p = "\n";
    write(2, p, strlen(p));

    if (echo)
    {
	term.c_lflag |= ECHO;
	(void) tcsetattr(1, TCSAFLUSH|TCSASOFT, &term);
    }

    return(pbuf);
}


static char *hw_passwd (void)
{
    char sbuf[40];
    static char buffer [12];
    struct nvram_info nvi;
    int    vidfd, count;
    
    if ((vidfd = open ("/dev/vid0", O_RDONLY, 0)) == -1)
	return NULL;
    
    if (ioctl (vidfd, DKIOCGNVRAM, &nvi) == -1)
	return NULL;
    
    if (nvi.ni_hw_pwd != HW_PWD)
	return NULL;
    else
    {

	for (count = 0; count < NVRAM_HW_PASSWD; count++)
	    nvi.ni_ep[count] ^= 'N';
	strncpy(buffer, nvi.ni_ep, NVRAM_HW_PASSWD);
	/* ni_ep is not necessarily null terminated */

	// gvdl I sure hope it is 'cause bad things will happen otherwise

	return buffer;
    }
}


#endif	m68k


static void
do_security_check(void)
{
#if m68k
    char sbuf[128];
    char *try, *passwd;
    int retries = 0;

    /*
     * If there is a hardware passwd, we want to 
     * prompt the user for it.  The write will be 
     * to the console window because of the O_POPUP flag.
     */
    passwd = hw_passwd();
    write (1, "\n\n", 2);

    if (passwd != NULL)
    {
	do
	{
	    try = gethwpasswd ("Enter hardware password:");
	    if (strncmp (try, passwd, NVRAM_HW_PASSWD) == 0)
	    {
		execl(shell, minus, (char *)0);
		exit (0);
	    }
	    else
	    {
		sprintf (sbuf, "Password incorrect.\n\n");
		write (1, sbuf, strlen (sbuf));
	    }
	}
	while (++retries < 3);
	do_halt();
    }
#elif defined(SECURE)
    struct ttyent *typ;
    struct passwd *pp;
    static const char banner[] =
	    "Enter root password, or ^D to go multi-user\n";
    char *clear, *password;

    /*
     * Check the root password.
     * We don't care if the console is 'on' by default;
     * it's the only tty that can be 'off' and 'secure'.
     */
    typ = getttynam("console");
    pp = getpwnam("root");
    if (typ && (typ->ty_status & TTY_SECURE) == 0 && pp)
    {
	write(2, banner, sizeof banner - 1);
	for (;;)
	{
	    clear = getpass("Password:");
	    if (clear == 0 || *clear == '\0')
		_exit(0);
	    password = crypt(clear, pp->pw_passwd);
	    memset(clear, 0, _PASSWORD_LEN);
	    if (strcmp(password, pp->pw_passwd) == 0)
		break;
	    warning("single-user login failed\n");
	}
    }
    endttyent();
    endpwent();
#endif /* SECURE */
}

/*
 * Bring the system up single user.
 */
state_func_t
single_user()
{
	pid_t pid, wpid;
	int status;
	sigset_t mask;
	char *shell = _PATH_BSHELL;
	char *argv[2];
	/*
	 * If the kernel is in secure mode, downgrade it to insecure mode.
	 */
	if (getsecuritylevel() > 0)
		setsecuritylevel(0);

	if ((pid = fork()) == 0) {
		/*
		 * Start the single user session.
		 */
		setctty(_PATH_CONSOLE, O_POPUP);

		do_security_check();

#ifdef DEBUGSHELL
		{
			char altshell[128], *cp = altshell;
			int num;

#define	SHREQUEST \
	"Enter pathname of shell or RETURN for sh: "
			(void)write(STDERR_FILENO,
			    SHREQUEST, sizeof(SHREQUEST) - 1);
			while ((num = read(STDIN_FILENO, cp, 1)) != -1 &&
			    num != 0 && *cp != '\n' && cp < &altshell[127])
					cp++;
			*cp = '\0';
			if (altshell[0] != '\0')
				shell = altshell;
		}
#endif /* DEBUGSHELL */

		/*
		 * Unblock signals.
		 * We catch all the interesting ones,
		 * and those are reset to SIG_DFL on exec.
		 */
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, (sigset_t *) 0);

                /*
                 * Set up the PATH to be approriate for the root user.
                 */
                setenv("PATH", _PATH_STDPATH, 1);

		/*
		 * We're dropping into the console; set TERM appropriately.
		 */
                setenv("TERM", "vt100", 1);

		/*
		 * Fire off a shell.
		 * If the default one doesn't work, try the Bourne shell.
		 */
		argv[0] = "-sh";
		argv[1] = 0;
		execv(shell, argv);
		emergency("can't exec %s for single user: %m", shell);
		execv(_PATH_BSHELL, argv);
		emergency("can't exec %s for single user: %m", _PATH_BSHELL);
		sleep(STALL_TIMEOUT);
		_exit(1);
	}

	if (pid == -1) {
		/*
		 * We are seriously hosed.  Do our best.
		 */
		emergency("can't fork single-user shell, trying again");
		while (waitpid(-1, (int *) 0, WNOHANG) > 0)
			continue;
		return (state_func_t) single_user;
	}

	requested_transition = 0;
	do {
		if ((wpid = waitpid(-1, &status, WUNTRACED)) != -1)
			collect_child(wpid);
		if (wpid == -1) {
			if (errno == EINTR)
				continue;
			warning("wait for single-user shell failed: %m; restarting");
			return (state_func_t) single_user;
		}
		if (wpid == pid && WIFSTOPPED(status)) {
			warning("init: shell stopped, restarting\n");
			kill(pid, SIGCONT);
			wpid = -1;
		}
	} while (wpid != pid && !requested_transition);

	if (requested_transition)
		return (state_func_t) requested_transition;

	if (!WIFEXITED(status)) {
		if (WTERMSIG(status) == SIGKILL) { 
			/* 
			 *  reboot(8) killed shell? 
			 */
			warning("single user shell terminated.");
			sleep(STALL_TIMEOUT);
			_exit(0);
		} else {	
			warning("single user shell terminated, restarting");
			return (state_func_t) single_user;
		}
	}

	runcom_mode = FASTBOOT;
	return (state_func_t) runcom;
}

/*
 * Run the system startup script.
 */
state_func_t
runcom()
{
	pid_t pid, wpid;
	int status;
	char *argv[4];
	char options[4];
	struct sigaction sa;

	if ((pid = fork()) == 0) {
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = SIG_IGN;
		(void) sigaction(SIGTSTP, &sa, (struct sigaction *)0);
		(void) sigaction(SIGHUP, &sa, (struct sigaction *)0);

		setctty(_PATH_CONSOLE, 0);

		argv[0] = "sh";

		if (runcom_mode == BOOT_SCRIPT)
		{
		    argv[1] = _PATH_RUNCOM_BOOT;
		    argv[2] = requested_transition == single_user
		    	    ? "singleuser" : "multiuser";
		}
		else /* runcom_mode != BOOT_SCRIPT */
		{
		    argv[1] = _PATH_RUNCOM;

		    switch(runcom_mode) {
		    case AUTOBOOT:
			argv[2] = "autoboot";
			break;
		    default:
			argv[2] = "multiuser";
			break;
		    }
		}

		if (runcom_verbose || runcom_safe)
		{
		    int i = 0;

		    options[i++] = '-';
		    if (runcom_verbose) options[i++] = 'v';
		    if (runcom_safe   ) options[i++] = 'x';
		    options[i] = '\0';

		    argv[3] = options;
		}
		else
		{
		    argv[3] = 0;
		}

		argv[4] = 0;

#ifdef DEBUG
		{
		    int i;
		    for (i = 0; i <= 4; i++) {
			if (argv[i])
			    warning("%s argument: %s", _PATH_RUNCOM, argv[i]);
		    }
		}
#endif

		sigprocmask(SIG_SETMASK, &sa.sa_mask, (sigset_t *) 0);

		execv(_PATH_BSHELL, argv);
		stall("can't exec %s for %s: %m", _PATH_BSHELL, _PATH_RUNCOM);
		_exit(1);	/* force single user mode */
	}

	if (pid == -1) {
		emergency("can't fork for %s on %s: %m",
			_PATH_BSHELL, _PATH_RUNCOM);
		while (waitpid(-1, (int *) 0, WNOHANG) > 0)
			continue;
		sleep(STALL_TIMEOUT);
		return (state_func_t) single_user;
	}

	/*
	 * Copied from single_user().  This is a bit paranoid.
	 */
	do {
		if ((wpid = waitpid(-1, &status, WUNTRACED)) != -1)
			collect_child(wpid);
		if (wpid == -1) {
			if (errno == EINTR)
				continue;
			warning("wait for %s on %s failed: %m; going to single user mode",
				_PATH_BSHELL, _PATH_RUNCOM);
			return (state_func_t) single_user;
		}
		if (wpid == pid && WIFSTOPPED(status)) {
			warning("init: %s on %s stopped, restarting\n",
				_PATH_BSHELL, _PATH_RUNCOM);
			kill(pid, SIGCONT);
			wpid = -1;
		}
	} while (wpid != pid);

	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM &&
	    requested_transition == catatonia) {
		/* /etc/rc executed /sbin/reboot; wait for the end quietly */
		sigset_t s;

		sigfillset(&s);
		for (;;)
			sigsuspend(&s);
	}

	if (!WIFEXITED(status)) {
		warning("%s on %s terminated abnormally, going to single user mode",
			_PATH_BSHELL, _PATH_RUNCOM);
		return (state_func_t) single_user;
	}

	if (WEXITSTATUS(status))
		return (state_func_t) single_user;

	runcom_mode = AUTOBOOT;		/* the default */
	/* NB: should send a message to the session logger to avoid blocking. */
	logwtmp("~", "reboot", "");
	return (state_func_t) read_ttys;
}

/*
 * Open the session database.
 *
 * NB: We could pass in the size here; is it necessary?
 */
int
start_session_db()
{
	if (session_db && (*session_db->close)(session_db))
		emergency("session database close: %s", strerror(errno));
	if ((session_db = dbopen(NULL, O_RDWR, 0, DB_HASH, NULL)) == 0) {
		emergency("session database open: %s", strerror(errno));
		return (1);
	}
	return (0);
		
}

/*
 * Add a new login session.
 */
void
add_session(sp)
	session_t *sp;
{
	DBT key;
	DBT data;

	key.data = &sp->se_process;
	key.size = sizeof sp->se_process;
	data.data = &sp;
	data.size = sizeof sp;

	if ((*session_db->put)(session_db, &key, &data, 0))
		emergency("insert %d: %s", sp->se_process, strerror(errno));
}

/*
 * Delete an old login session.
 */
void
del_session(sp)
	session_t *sp;
{
	DBT key;

	key.data = &sp->se_process;
	key.size = sizeof sp->se_process;

	if ((*session_db->del)(session_db, &key, 0))
		emergency("delete %d: %s", sp->se_process, strerror(errno));
}

/*
 * Look up a login session by pid.
 */
session_t *
find_session(pid_t pid)
{
	DBT key;
	DBT data;
	session_t *ret;

	key.data = &pid;
	key.size = sizeof pid;
	if ((*session_db->get)(session_db, &key, &data, 0) != 0)
		return 0;
	memmove(&ret, data.data, sizeof(ret));
	return ret;
}

/*
 * Construct an argument vector from a command line.
 */
char **
construct_argv(command)
	char *command;
{
	register int argc = 0;
	register char **argv = (char **) malloc(((strlen(command) + 1) / 2 + 1)
						* sizeof (char *));
	static const char separators[] = " \t";

	if ((argv[argc++] = strtok(command, separators)) == 0)
		return 0;
	while ((argv[argc++] = strtok((char *) 0, separators)))
		continue;
	return argv;
}

/*
 * Deallocate a session descriptor.
 */

static __inline__ void free_command(se_cmd_t *se_cmd)
{
    if (se_cmd->path)
    {
	free(se_cmd->path);
	free(se_cmd->argv);
    }
}

void
free_session(sp)
	register session_t *sp;
{
    free(sp->se_device);
    free_command(&sp->se_getty);
    free_command(&sp->se_window);
    free_command(&sp->se_onerror);
    free_command(&sp->se_onoption);
    memset(sp, '\0', sizeof(*sp));	// a bit of defensive programming

    free(sp);
}

static int setup_command(se_cmd_t *se_cmd, char *command, char *arg )
{

    char *commandWithArg;

    commandWithArg = malloc( strlen( command) + strlen( arg) + 2);
    (void) sprintf(commandWithArg, "%s %s", command, arg);

	free_command(se_cmd);

	se_cmd->path = commandWithArg;
	se_cmd->argv = construct_argv(commandWithArg);
	if (se_cmd->argv == NULL)
	{
		free(se_cmd->path);
		se_cmd->path = NULL;
		return 0;
	}
	return 1;
}

/*
 * Calculate getty and if useful window argv vectors.
 */
int
setupargv(sp, typ)
	session_t *sp;
	struct ttyent *typ;
{
    char *type;

    if ( !setup_command(&sp->se_getty, typ->ty_getty, typ->ty_name) )
    {
	type = "getty";
	goto bad_args;
    }

    if (typ->ty_window
    && !setup_command(&sp->se_window, typ->ty_window, typ->ty_name) )
    {
	type = "window";
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
    warning("can't parse %s for port %s", type, sp->se_device);
    return 0;
}


/*
 * Allocate a new session descriptor.
 */
session_t *
new_session(sprev, session_index, typ)
	session_t *sprev;
	int session_index;
	register struct ttyent *typ;
{
	register session_t *sp;

	if ((typ->ty_status & TTY_ON) == 0 ||
	    typ->ty_name == 0 ||
	    typ->ty_getty == 0)
		return 0;

	sp = (session_t *) malloc(sizeof (session_t));
	memset(sp, 0, sizeof *sp);

	sp->se_index = session_index;

	sp->se_device = malloc(sizeof(_PATH_DEV) + strlen(typ->ty_name));
	(void) sprintf(sp->se_device, "%s%s", _PATH_DEV, typ->ty_name);

	if (setupargv(sp, typ) == 0) {
		free_session(sp);
		return (0);
	}

	sp->se_next = 0;
	if (sprev == 0) {
		sessions = sp;
		sp->se_prev = 0;
	} else {
		sprev->se_next = sp;
		sp->se_prev = sprev;
	}

	return sp;
}

/*
 * Walk the list of ttys and create sessions for each active line.
 */
state_func_t
read_ttys()
{
	int session_index = 0;
	register session_t *sp, *snext;
	register struct ttyent *typ;

	/*
	 * Destroy any previous session state.
	 * There shouldn't be any, but just in case...
	 */
	for (sp = sessions; sp; sp = snext) {
		if (sp->se_process)
			clear_session_logs(sp);
		snext = sp->se_next;
		free_session(sp);
	}
	sessions = 0;
	if (start_session_db())
		return (state_func_t) single_user;

	/*
	 * Allocate a session entry for each active port.
	 * Note that sp starts at 0.
	 */
	while ((typ = getttyent()))
		if ((snext = new_session(sp, ++session_index, typ)))
			sp = snext;

	endttyent();

	return (state_func_t) multi_user;
}

/*
 * Start a window system running.
 */
static pid_t
start_window_system(session_t *sp)
{
	pid_t pid;
	sigset_t mask;

	if ((pid = fork()) == -1) {
		emergency("can't fork for window system on port %s: %m",
			sp->se_device);
		/* hope that getty fails and we can try again */
		return -1;
	}

	if (pid)
		return pid;

	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, (sigset_t *) 0);

	if (setsid() < 0)
		emergency("setsid failed (window) %m");

	execv(sp->se_window.argv[0], sp->se_window.argv);
	stall("can't exec window system '%s' for port %s: %m",
		sp->se_window.argv[0], sp->se_device);
	_exit(1);
}

/*
 * Start a login session running.
 */
pid_t
start_getty(sp)
	session_t *sp;
{
	pid_t pid;
	sigset_t mask;
	se_cmd_t *se_cmd;
	const char *session_type = NULL;
	time_t current_time      = time((time_t *) 0);

	// Setup the default values;
	switch (sp->se_flags & SE_GETTY_LAUNCH)
	{
	case SE_ONOPTION:
	    if (sp->se_onoption.path)
	    {
		se_cmd       = &sp->se_onoption;
		session_type = "onoption";
		break;
	    }
	    /* No break */

	case SE_ONERROR:
	    if (sp->se_onerror.path)
	    {
		se_cmd       = &sp->se_onerror;
		session_type = "onerror";
		break;
	    }
	    /* No break */

	case SE_COMMON:
	default:
	    se_cmd       = &sp->se_getty;
	    session_type = "getty";
	    break;
	}

	if  (sp->se_window.path
	&& ((sp->se_flags & SE_GETTY_LAUNCH) != SE_ONOPTION))
	{
		if (start_window_system(sp) == -1)
		        return -1;
	}

	/*
	 * fork(), not vfork() -- we can't afford to block.
	 */
	if ((pid = fork()) == -1) {
		emergency("can't fork for %s on port %s: %m",
		    session_type, sp->se_device);
		return -1;
	}

	if (pid)
		return pid;

	if (current_time > sp->se_started &&
	    current_time - sp->se_started < GETTY_SPACING) {
		warning("%s repeating too quickly on port %s, sleeping",
		        session_type, sp->se_device);
		sleep((unsigned) GETTY_SLEEP);
	}

	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, (sigset_t *) 0);

	execv(se_cmd->argv[0], se_cmd->argv);
	stall("can't exec %s '%s' for port %s: %m", session_type,
		se_cmd->argv[0], sp->se_device);
	_exit(1);
}

/*
 * Collect exit status for a child.
 * If an exiting login, start a new login running.
 */
void
collect_child(pid_t pid)
{
	register session_t *sp, *sprev, *snext;

	if ( !sessions)
		return;

	if ( !(sp = find_session(pid)) )
		return;

	clear_session_logs(sp);
	del_session(sp);
	sp->se_process = 0;

	if (sp->se_flags & SE_SHUTDOWN) {
		if ((sprev = sp->se_prev))
			sprev->se_next = sp->se_next;
		else
			sessions = sp->se_next;
		if ((snext = sp->se_next))
			snext->se_prev = sp->se_prev;
		free_session(sp);
		return;
	}

	if ((pid = start_getty(sp)) == -1) {
		/* serious trouble */
		requested_transition = clean_ttys;
		return;
	}

	sp->se_process = pid;
	sp->se_started = time((time_t *) 0);
	sp->se_flags  &= ~SE_GETTY_LAUNCH; // clear down getty launch type
	add_session(sp);
}

/*
 * Catch a signal and request a state transition.
 */
void
transition_handler(sig)
	int sig;
{

	switch (sig) {
	case SIGHUP:
		requested_transition = clean_ttys;
		break;
	case SIGTERM:
		requested_transition = death;
		break;
	case SIGTSTP:
		requested_transition = catatonia;
		break;
	default:
		requested_transition = 0;
		break;
	}
}

/*
 * Take the system multiuser.
 */
state_func_t
multi_user()
{
	pid_t pid;
	register session_t *sp;

	requested_transition = 0;

	/*
	 * If the administrator has not set the security level to -1
	 * to indicate that the kernel should not run multiuser in secure
	 * mode, and the run script has not set a higher level of security 
	 * than level 1, then put the kernel into secure mode.
	 */
	if (getsecuritylevel() == 0)
		setsecuritylevel(1);

	for (sp = sessions; sp; sp = sp->se_next) {
		if (sp->se_process)
			continue;
		if ((pid = start_getty(sp)) == -1) {
			/* serious trouble */
			requested_transition = clean_ttys;
			break;
		}
		sp->se_process = pid;
		sp->se_started = time((time_t *) 0);
		add_session(sp);
	}

	while (!requested_transition)
	{
		int status;

		pid = waitpid(-1, &status, 0);
		if (!sessions || !(sp = find_session(pid)))
			continue;

		if (WIFSIGNALED(status))
		    sp->se_flags |= SE_ONERROR;
		else if (WEXITSTATUS(status) == REALLY_EXIT_TO_CONSOLE)
		{ /* WIFEXITED(status) assumed */
		    sp->se_flags |= SE_ONOPTION;
		}
		else
		    sp->se_flags |= SE_ONERROR;

		if (pid != -1)
			collect_child(pid);
	}

	return (state_func_t) requested_transition;
}

/*
 * This is an n-squared algorithm.  We hope it isn't run often...
 */
state_func_t
clean_ttys()
{
	register session_t *sp, *sprev;
	register struct ttyent *typ;
	register int session_index = 0;
	register int devlen;

	if (! sessions)
		return (state_func_t) multi_user;

	devlen = sizeof(_PATH_DEV) - 1;
	while ((typ = getttyent())) {
		++session_index;

		for (sprev = 0, sp = sessions; sp; sprev = sp, sp = sp->se_next)
			if (strcmp(typ->ty_name, sp->se_device + devlen) == 0)
				break;

		if (sp) {
			if (sp->se_index != session_index) {
				warning("port %s changed utmp index from %d to %d",
				       sp->se_device, sp->se_index,
				       session_index);
				sp->se_index = session_index;
			}
			if ((typ->ty_status & TTY_ON) == 0 ||
			    typ->ty_getty == 0) {
				sp->se_flags |= SE_SHUTDOWN;
				kill(sp->se_process, SIGHUP);
				continue;
			}
			sp->se_flags &= ~SE_SHUTDOWN;
			if (setupargv(sp, typ) == 0) {
				warning("can't parse getty for port %s",
					sp->se_device);
				sp->se_flags |= SE_SHUTDOWN;
				kill(sp->se_process, SIGHUP);
			}
			continue;
		}

		new_session(sprev, session_index, typ);
	}

	endttyent();

	return (state_func_t) multi_user;
}

/*
 * Block further logins.
 */
state_func_t
catatonia()
{
	register session_t *sp;

	for (sp = sessions; sp; sp = sp->se_next)
		sp->se_flags |= SE_SHUTDOWN;

	return (state_func_t) multi_user;
}

/*
 * Note SIGALRM.
 */
void
alrm_handler(sig)
	int sig __attribute__((unused));
{
	clang = 1;
}

/*
 * Bring the system down to single user.
 */
state_func_t
death()
{
	register session_t *sp;
	register int i;
	pid_t pid;
	static const int death_sigs[3] = { SIGHUP, SIGTERM, SIGKILL };

	for (sp = sessions; sp; sp = sp->se_next)
		sp->se_flags |= SE_SHUTDOWN;

	/* NB: should send a message to the session logger to avoid blocking. */
	logwtmp("~", "shutdown", "");

	for (i = 0; i < 3; ++i) {
		if (kill(-1, death_sigs[i]) == -1 && errno == ESRCH)
			return (state_func_t) single_user;

		clang = 0;
		alarm(DEATH_WATCH);
		do
			if ((pid = waitpid(-1, (int *)0, 0)) != -1)
				collect_child(pid);
		while (clang == 0 && errno != ECHILD);

		if (errno == ECHILD)
			return (state_func_t) single_user;
	}

	warning("some processes would not die; ps axl advised");

	return (state_func_t) single_user;
}
