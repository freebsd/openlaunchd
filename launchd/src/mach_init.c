/*
 * Copyright (c) 1999-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * bootstrap -- fundamental service initiator and port server
 * Mike DeMoney, NeXT, Inc.
 * Copyright, 1990.  All rights reserved.
 *
 * bootstrap.c -- implementation of bootstrap main service loop
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <paths.h>
#include <fcntl.h>
#include <syslog.h>


#include "bootstrap.h"
#include "bootstrap_internal.h"
#include "lists.h"

#ifndef INIT_PATH
#define INIT_PATH	"/sbin/launchd"
#endif  INIT_PATH

static void toggle_debug(int);
static void enablecoredumps(bool);

mach_port_t launchd_bootstrap_port = MACH_PORT_NULL;
sigset_t blocked_signals = 0;

int
main(int argc, char * argv[])
{
	bool force_fork = false;
	sigset_t mask;
	int ch;

	if (getpid() == 1) {
		argv[0] = INIT_PATH;
		execv(INIT_PATH, argv);
		exit(EXIT_FAILURE);
	}

	sigemptyset(&blocked_signals);

	while ((ch = getopt(argc, argv, "dFr:")) != -1) {
		switch (ch) {
		case 'd':
			debugging = true;
			break;
		case 'F':
			force_fork = true;
			break;
		case 'r':
			register_self = forward_ok = true;
			register_name = optarg;
			break;
		default:
			break;
		}
	}

	/*
	 * If we must fork, do it now before we get Mach ports in use
	 */
	switch (force_fork ? fork() : 0) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "fork(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	default:
		exit(EXIT_SUCCESS);
	}

	if (!debugging) {
		close(STDIN_FILENO);
		open(_PATH_DEVNULL, O_RDONLY, 0);
		close(STDOUT_FILENO);
		open(_PATH_DEVNULL, O_WRONLY, 0);
		close(STDERR_FILENO);
		open(_PATH_DEVNULL, O_WRONLY, 0);
	}
	enablecoredumps(debugging);

	openlog(getprogname(), LOG_PID|(debugging ? LOG_PERROR : 0), LOG_DAEMON);

	setsid();

	/* block all but SIGHUP and SIGTERM  */
	sigfillset(&mask);
	sigdelset(&mask, SIGHUP);
	signal(SIGHUP, toggle_debug);
	sigdelset(&mask, SIGTERM);
	signal(SIGTERM, mach_start_shutdown);
	(void) sigprocmask(SIG_SETMASK, &mask, (sigset_t *)NULL);

	mach_init_init();
	
	syslog(LOG_NOTICE, "Started with uid=%d%s%s%s",
		getuid(),
		(register_self) ? " registered-as=" : "",
		(register_self) ? register_name : "",
		(debugging) ? " in debug-mode" : "");

	mach_server_loop(NULL);

	exit(EXIT_FAILURE);
}

static void
enablecoredumps(bool enabled)
{
	struct rlimit rlimit;

	getrlimit(RLIMIT_CORE, &rlimit);
	rlimit.rlim_cur = (enabled) ? rlimit.rlim_max : 0;
	setrlimit(RLIMIT_CORE, &rlimit);
}

static void
toggle_debug(int signalnum __attribute__((unused)))
{
	debugging = (debugging) ? false : true;
	enablecoredumps(debugging);
}       
