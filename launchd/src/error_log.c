/*
 * Copyright (c) 1999-2003 Apple Computer, Inc. All rights reserved.
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
 * error_log.c -- implementation of logging routines
 *
 * Routines may be safely invoked from multiple threads
 */

#import <pthread.h>
#import <mach/mach_error.h>
#import <stdio.h>
#import <syslog.h>
#import <sys/syslimits.h>
#import <libc.h>
#import	<errno.h>

#import "bootstrap_internal.h"
#import "error_log.h"

static pthread_mutex_t errlog_lock = PTHREAD_MUTEX_INITIALIZER;
static boolean_t stderr_open = FALSE;
static boolean_t log_stopped = FALSE;

void
init_errlog(boolean_t start_as_daemon)
{
	int nfds, fd;

	if (!start_as_daemon) {
		stderr_open = TRUE; 
		nfds = getdtablesize();
		for (fd = 3; fd < nfds; fd++)
			close(fd);
	} else {
		openlog((char *)program_name, LOG_PID|LOG_CONS, LOG_DAEMON);
		setlogmask(LOG_UPTO(LOG_DEBUG)); /* we'll do our own filtering */
	}
}

void
stop_errlog(void)
{
	log_stopped = TRUE;
}

void
close_errlog(void)
{
	stop_errlog();
	closelog();
}

static void do_log(const int level, const char *format, va_list ap)
{
	if (!log_stopped && (debugging || level <= LOG_NOTICE)) {
		pthread_mutex_lock(&errlog_lock);
		if (stderr_open) {
			fprintf(stderr, "%s[%d]%s: ",
				level == LOG_ALERT ? " FATAL" : "",
				getpid(), program_name);
			vfprintf(stderr, format, ap);
			fprintf(stderr, "\n");
		} else {
			vsyslog(level, format, ap);
		}
		pthread_mutex_unlock(&errlog_lock);
	}
}

void debug(const char *format, ...)
{
    if (debugging) {
	va_list ap;
	
	va_start(ap, format);
	do_log(LOG_DEBUG, format, ap);
	va_end(ap);
    }
}

void info(const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	do_log(LOG_INFO, format, ap);
	va_end(ap);
}

void notice(const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	do_log(LOG_NOTICE, format, ap);
	va_end(ap);
}

void error(const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	do_log(LOG_CRIT, format, ap);
	va_end(ap);
}

void kern_error(kern_return_t result, const char *format, ...)
{
	va_list ap;
	char buf[1000];
	
	sprintf(buf, "%s: %s(%d)", format, mach_error_string(result), result);

	va_start(ap, format);
	do_log(LOG_CRIT, buf, ap);
	va_end(ap);
}

void unix_error(const char *format, ...)
{
	va_list ap;
	char buf[1000];
	
	sprintf(buf, "%s: %s(%d)", format, strerror(errno), errno);

	va_start(ap, format);
	do_log(LOG_CRIT, buf, ap);
	va_end(ap);
}

void parse_error(const char *token_string, const char *format, ...)
{
	va_list ap;
	char buf[1000];

	sprintf(buf, "%s unexpected: %s", token_string, format);

	va_start(ap, format);
	do_log(LOG_CRIT, buf, ap);
	va_end(ap);
}

void fatal(const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	do_log(LOG_ALERT, format, ap);
	va_end(ap);
	exit(1);
}

void kern_fatal(kern_return_t result, const char *format, ...)
{
	va_list ap;
	char buf[1000];
	
	sprintf(buf, "%s: %s(%d)", format, mach_error_string(result), result);

	va_start(ap, format);
	do_log(LOG_ALERT, buf, ap);
	va_end(ap);
	exit(1);
}

void unix_fatal(const char *format, ...)
{
	va_list ap;
	char buf[1000];
	
	sprintf(buf, "%s: %s(%d)", format, strerror(errno), errno);

	va_start(ap, format);
	do_log(LOG_ALERT, buf, ap);
	va_end(ap);
	exit(1);
}
