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

/*
 * Imports
 */
#import	<mach/mach.h>
#import <mach/mach_error.h>
#import	<mach/boolean.h>
#import	<mach/message.h>
#import <mach/notify.h>
#import <mach/mig_errors.h>
#include <mach/mach_traps.h>
#include <mach/mach_interface.h>
#include <mach/bootstrap.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/exception.h>

#import <sys/ioctl.h>
#import <sys/types.h>
#import <sys/time.h>
#import <sys/resource.h>
#import <sys/wait.h>
#import <pthread.h>
#import	<string.h>
#import	<ctype.h>
#import	<stdio.h>
#import <libc.h>
#import <paths.h>

#import "bootstrap.h"

#import "bootstrap_internal.h"
#import "lists.h"
#import "error_log.h"

/* Mig should produce a declaration for this,  but doesn't */
extern boolean_t bootstrap_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

#ifndef INIT_PATH
#define INIT_PATH	"/sbin/launchd"			/* default init path */
#endif  INIT_PATH

uid_t inherited_uid;
mach_port_t inherited_bootstrap_port = MACH_PORT_NULL;
boolean_t forward_ok = FALSE;
boolean_t shutdown_in_progress = FALSE;
boolean_t debugging = FALSE;
boolean_t register_self = FALSE;
boolean_t force_fork = FALSE;
const char *register_name;
task_t	bootstrap_self;

#ifndef ASSERT
#define ASSERT(p)
#endif

/*
 * Private macros
 */
#define	NELEM(x)		(sizeof(x)/sizeof(x[0]))
#define	END_OF(x)		(&(x)[NELEM(x)])
#define	streq(a,b)		(strcmp(a,b) == 0)

/*
 * Private declarations
 */	
static void wait_for_go(mach_port_t init_notify_port);
static void init_ports(void);
static void start_server(server_t *serverp);
static void unblock_init(mach_port_t init_notify_port, mach_port_t newBootstrap);
static void exec_server(server_t *serverp);
static char **argvize(const char *string);
static void *demand_loop(void *arg);
static void server_loop(void);
extern kern_return_t bootstrap_register
(
	mach_port_t bootstrapport,
	name_t servicename,
	mach_port_t serviceport
);

/*
 * Private ports we hold receive rights for.  We also hold receive rights
 * for all the privileged ports.  Those are maintained in the server
 * structs.
 */
mach_port_t bootstrap_port_set;
mach_port_t demand_port_set;
pthread_t	demand_thread;

mach_port_t notify_port;
mach_port_t backup_port;


static void
enablecoredumps(boolean_t enabled)
{
	struct rlimit rlimit;

	getrlimit(RLIMIT_CORE, &rlimit);
	rlimit.rlim_cur = (enabled) ? rlimit.rlim_max : 0;
	setrlimit(RLIMIT_CORE, &rlimit);
}

static void
toggle_debug(__unused int signalnum)
{

	debugging = (debugging) ? FALSE : TRUE;
	enablecoredumps(debugging);
}

static mach_msg_return_t
inform_server_loop(
        mach_port_name_t about,
	mach_msg_option_t options)
{
	mach_port_destroyed_notification_t not;
	mach_msg_size_t size = sizeof(not) - sizeof(not.trailer);

	not.not_header.msgh_id = DEMAND_REQUEST;
	not.not_header.msgh_remote_port = backup_port;
	not.not_header.msgh_local_port = MACH_PORT_NULL;
	not.not_header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
	not.not_header.msgh_size = size;
	not.not_body.msgh_descriptor_count = 1;
	not.not_port.type = MACH_MSG_PORT_DESCRIPTOR;
	not.not_port.disposition = MACH_MSG_TYPE_PORT_NAME;
	not.not_port.name = about;
	return mach_msg(&not.not_header, MACH_SEND_MSG|options, size,
			0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void
notify_server_loop(mach_port_name_t about)
{
	mach_msg_return_t result;

	result = inform_server_loop(about, MACH_MSG_OPTION_NONE);
	if (result != MACH_MSG_SUCCESS)
		kern_error(result, "notify_server_loop: mach_msg()");
}

void start_shutdown(__unused int signalnum)
{
	shutdown_in_progress = TRUE;
	(void) inform_server_loop(MACH_PORT_NULL, MACH_SEND_TIMEOUT);
}

int
main(int argc, char * argv[])
{
	kern_return_t result;
	mach_port_t init_notify_port;
	pthread_attr_t  attr;
	sigset_t mask;
	int ch, pid;

	/*
	 * If we are pid one, we have to exec init.  Before doing so, we'll
	 * fork a child, and that will become the true mach_init.  But we have
	 * to be very careful about ports.  They aren't inherited across fork,
	 * so we have to avoid storing port names in memory before the fork that
	 * might not be valid after.
	 */
	pid = getpid();
	if (pid == 1)
	{
		result = mach_port_allocate(
						mach_task_self(),
						MACH_PORT_RIGHT_RECEIVE,
						&init_notify_port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_allocate");

		result = mach_port_insert_right(
						mach_task_self(),
						init_notify_port,
						init_notify_port,
						MACH_MSG_TYPE_MAKE_SEND);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_insert_right");

		result = task_set_bootstrap_port(
						mach_task_self(),
						init_notify_port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "task_set_bootstrap_port");

		pid = fork();

		if (pid < 0)
			unix_fatal("fork");

		else if (pid != 0) {  /* PARENT - will become init when ready */
			int fd;

			/*
			 * Wait for mach_init ot give us a real bootstrap port
			 */
			wait_for_go(init_notify_port);

			close(0);
			close(1);
			close(2);
			fd = open("/dev/tty", O_RDONLY);
			if (fd >= 0) {
				ioctl(fd, TIOCNOTTY, 0);
				close(fd);
			}
			
			argv[0] = INIT_PATH;
			execv(INIT_PATH, argv);
			exit(EXIT_FAILURE);  /* will likely trigger a panic */

		}

		/*
		 * Child - will continue along as mach_init.  Save off
		 * the init_notify_port and put back a NULL bootstrap
		 * port for ourselves.
		 */
		init_notify_port = bootstrap_port;
		bootstrap_port = MACH_PORT_NULL;
		(void)task_set_bootstrap_port(
							mach_task_self(),
							bootstrap_port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "task_get_bootstrap_port");

		close(0);
		open("/dev/null", O_RDONLY, 0);
		close(1);
		open("/dev/null", O_WRONLY, 0);
		close(2);
		open("/dev/null", O_WRONLY, 0);

	} else
		init_notify_port = MACH_PORT_NULL;

	while ((ch = getopt(argc, argv, "dDFr:vsbx")) != -1) {
		switch (ch) {
		case 'd':
			debugging = TRUE;
			break;
		case 'D':
			debugging = FALSE;
			break;
		case 'F':
			if (init_notify_port != MACH_PORT_NULL)
				force_fork = TRUE;
			break;
		case 'r':
			register_self = forward_ok = TRUE;
			register_name = optarg;
			break;
		default:
			break;
		}
	}

	/*
	 * If we must fork, do it now before we get Mach ports in use
	 */
	if (force_fork) {
		pid = fork();
		if (pid < 0)
			unix_fatal("fork");
		else if (pid != 0) /* PARENT: just exit */
			exit(0);
	}

	/*
	 *	This task will become the bootstrap task, initialize the ports.
	 */
	bootstrap_self = mach_task_self();
	inherited_uid = getuid();
	init_lists();
	init_ports();

	if (init_notify_port != MACH_PORT_NULL) {
		/* send init a real bootstrap port to use */
		unblock_init(init_notify_port, bootstraps.bootstrap_port);

		result = mach_port_deallocate(
							bootstrap_self,
							init_notify_port);  
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_deallocate");

		forward_ok = FALSE;
		inherited_bootstrap_port = MACH_PORT_NULL;

	} else {
		/* get inherited bootstrap port */
		result = task_get_bootstrap_port(
							bootstrap_self,
							&inherited_bootstrap_port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "task_get_bootstrap_port");

		/* We set this explicitly as we start each child */
		task_set_bootstrap_port(bootstrap_self, MACH_PORT_NULL);
		if (inherited_bootstrap_port == MACH_PORT_NULL)
			forward_ok = FALSE;

		/* register "self" port with anscestor */		
		if (register_self && forward_ok) {
			result = bootstrap_register(
							inherited_bootstrap_port,
							(char *)register_name,
							bootstraps.bootstrap_port);
			if (result != KERN_SUCCESS)
				kern_fatal(result, "register self");
		}
	}

	pthread_attr_init (&attr);
	pthread_attr_setdetachstate ( &attr, PTHREAD_CREATE_DETACHED );
	result = pthread_create(
						&demand_thread,
						&attr,
						demand_loop,
						NULL);
	if (result)
		unix_fatal("pthread_create()");
	
	/* block all but SIGHUP and SIGTERM  */
	sigfillset(&mask);
	sigdelset(&mask, SIGHUP);
	signal(SIGHUP, toggle_debug);
	sigdelset(&mask, SIGTERM);
	signal(SIGTERM, start_shutdown);
	(void) sigprocmask(SIG_SETMASK, &mask, (sigset_t *)NULL);

	/* 
	 * Construct a very basic environment - as much as if we
	 * were actually forked from init (instead of the other
	 * way around):
	 *
	 * Set up the PATH to be approriate for the root user.
	 * Create an initial session.
	 * Establish an initial user.
	 * Disbale core dumps.
	 */
	setsid();
	setlogin("root");
	enablecoredumps(debugging);
	setenv("PATH", _PATH_STDPATH, 1);

	init_errlog(pid == 0); /* are we a daemon? */
	notice("Started with uid=%d%s%s%s",
		inherited_uid,
		(register_self) ? " registered-as=" : "",
		(register_self) ? register_name : "",
		(debugging) ? " in debug-mode" : "");

	/* Process bootstrap service requests */
	server_loop();	/* Should never return */
	exit(1);
}

static void
wait_for_go(mach_port_t init_notify_port)
{
	struct {
            mach_msg_header_t hdr;
            mach_msg_trailer_t trailer;
	} init_go_msg;
	kern_return_t result;

	/*
	 * For now, we just blindly wait until we receive a message or
	 * timeout.  We don't expect any notifications, and if we get one,
	 * it probably means something dire has happened; so we might as
	 * well give a shot at letting init run.
	 */	
	result = mach_msg(
						&init_go_msg.hdr, MACH_RCV_MSG,
						0, sizeof(init_go_msg), init_notify_port,
						MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (result != KERN_SUCCESS) {
		kern_error(result, "mach_msg(receive) failed in wait_for_go");
	}
	bootstrap_port = init_go_msg.hdr.msgh_remote_port;
	result = task_set_bootstrap_port(
						mach_task_self(),
						bootstrap_port);
	if (result != KERN_SUCCESS) {
		kern_error(result, "task_get_bootstrap_port()");
	}
}


static void
unblock_init(mach_port_t init_notify_port, 
			 mach_port_t newBootstrap)
{
	mach_msg_header_t init_go_msg;
	kern_return_t result;

	/*
	 * Proc 1 is blocked in a msg_receive on its notify port, this lets
	 * it continue, and we hand off its new bootstrap port
	 */
	init_go_msg.msgh_remote_port = init_notify_port;
	init_go_msg.msgh_local_port = newBootstrap;
        init_go_msg.msgh_bits = MACH_MSGH_BITS(
								MACH_MSG_TYPE_COPY_SEND,
								MACH_MSG_TYPE_MAKE_SEND);
	init_go_msg.msgh_size = sizeof(init_go_msg);
        result = mach_msg_send(&init_go_msg);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "unblock_init mach_msg_send() failed");
	debug("sent go message");
}


static void
init_ports(void)
{
	kern_return_t result;

	/*
	 *	This task will become the bootstrap task.
	 */
	/* Create port set that server loop listens to */
	result = mach_port_allocate(
						bootstrap_self,
						MACH_PORT_RIGHT_PORT_SET,
						&bootstrap_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "port_set_allocate");

	/* Create demand port set that second thread listens to */
	result = mach_port_allocate(
						bootstrap_self,
						MACH_PORT_RIGHT_PORT_SET,
						&demand_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "port_set_allocate");

	/* Create notify port and add to server port set */
	result = mach_port_allocate(
						bootstrap_self,
						MACH_PORT_RIGHT_RECEIVE,
						&notify_port);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_allocate");

	result = mach_port_move_member(
						bootstrap_self,
						notify_port,
						bootstrap_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_move_member");
	
	/* Create backup port and add to server port set */
	result = mach_port_allocate(
						bootstrap_self,
						MACH_PORT_RIGHT_RECEIVE,
						&backup_port);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_allocate");

	result = mach_port_move_member(
						bootstrap_self,
						backup_port,
						bootstrap_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_move_member");
	
	/* Create "self" port and add to server port set */
	result = mach_port_allocate(
						bootstrap_self,
						MACH_PORT_RIGHT_RECEIVE,
						&bootstraps.bootstrap_port);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_allocate");
	result = mach_port_insert_right(
						bootstrap_self,
						bootstraps.bootstrap_port,
						bootstraps.bootstrap_port,
						MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_insert_right");

	/* keep the root bootstrap port "active" */
	bootstraps.requestor_port = bootstraps.bootstrap_port;

	result = mach_port_move_member(
						bootstrap_self,
						bootstraps.bootstrap_port,
						bootstrap_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_move_member");
}

boolean_t
active_bootstrap(bootstrap_info_t *bootstrap)
{
	return (bootstrap->requestor_port != MACH_PORT_NULL);
}

boolean_t
useless_server(server_t *serverp)
{
	return (	!active_bootstrap(serverp->bootstrap) || 
				!lookup_service_by_server(serverp) ||
				!serverp->activity);
}

boolean_t
active_server(server_t *serverp)
{
	return (	serverp->port ||
			serverp->task_port || serverp->active_services);
}

static void
reap_server(server_t *serverp)
{
	kern_return_t result;
	pid_t	presult;
	int		wstatus;

	/*
	 * Reap our children.
	 */
	presult = waitpid(serverp->pid, &wstatus, WNOHANG);
	switch (presult) {
	case -1:
		unix_error("waitpid: cmd = %s", serverp->cmd);
		break;

	case 0:
	{
		/* process must have switched mach tasks */
		mach_port_t old_port;

		old_port = serverp->task_port;
		mach_port_deallocate(mach_task_self(), old_port);
		serverp->task_port = MACH_PORT_NULL;

		result = task_for_pid(	mach_task_self(),
					serverp->pid,
					&serverp->task_port);
		if (result != KERN_SUCCESS) {
			info("race getting new server task port for pid[%d]: %s",
			     serverp->pid, mach_error_string(result));
			break;
		}

		/* Request dead name notification to tell when new task dies */
		result = mach_port_request_notification(
					mach_task_self(),
					serverp->task_port,
					MACH_NOTIFY_DEAD_NAME,
					0,
					notify_port,
					MACH_MSG_TYPE_MAKE_SEND_ONCE,
					&old_port);
		if (result != KERN_SUCCESS) {
			info("race setting up notification for new server task port for pid[%d]: %s",
			     serverp->pid, mach_error_string(result));
			break;
		}
		return;
	}

	default:
		if (wstatus) {
			notice("Server %x in bootstrap %x uid %d: \"%s\": %s %d [pid %d]",
			       serverp->port, serverp->bootstrap->bootstrap_port,
			       serverp->uid, serverp->cmd, 
			       ((WIFEXITED(wstatus)) ? 
				"exited with non-zero status" :
				"exited as a result of signal"),
			       ((WIFEXITED(wstatus)) ? WEXITSTATUS(wstatus) : WTERMSIG(wstatus)),
			       serverp->pid);
		}
		break;
	}
		

	serverp->pid = 0;

	/*
	 * Release the server task port reference, if we ever
	 * got it in the first place.
	 */
	if (serverp->task_port != MACH_PORT_NULL) {
		result = mach_port_deallocate(
					mach_task_self(),
					serverp->task_port);
		if (result != KERN_SUCCESS)
			kern_error(result, "mach_port_deallocate");
		serverp->task_port = MACH_PORT_NULL;
	}
}

static void
demand_server(server_t *serverp)
{
	service_t *servicep;
	kern_return_t result;

	/*
	 * For on-demand servers, make sure that the service ports are
	 * back in on-demand portset.  Active service ports should come
	 * back through a PORT_DESTROYED notification.  We only have to
	 * worry about the inactive ports that may have been previously
	 * pulled from the set but never checked-in by the server.
	 */

	for (  servicep = FIRST(services)
			   ; !IS_END(servicep, services)
			   ; servicep = NEXT(servicep))
	{
		if (serverp == servicep->server && !servicep->isActive) {
			result = mach_port_move_member(
							mach_task_self(),
							servicep->port,
							demand_port_set);
			if (result != KERN_SUCCESS)
				kern_fatal(result, "mach_port_move_member");
		}
	}
}

static
void dispatch_server(server_t *serverp)
{
	if (!active_server(serverp)) {
		if (useless_server(serverp))
			delete_server(serverp);
		else if (serverp->servertype == RESTARTABLE)
			start_server(serverp);
		else if (serverp->servertype == DEMAND)
			demand_server(serverp);
	}
}

void
setup_server(server_t *serverp)
{
	kern_return_t result;
	mach_port_t old_port;
	
	/* Allocate privileged port for requests from service */
	result = mach_port_allocate(mach_task_self(),
						MACH_PORT_RIGHT_RECEIVE ,
						&serverp->port);
	info("Allocating port %x for server %s", serverp->port, serverp->cmd);
	if (result != KERN_SUCCESS)	
		kern_fatal(result, "port_allocate");

	/* Request no-senders notification so we can tell when server dies */
	result = mach_port_request_notification(mach_task_self(),
						serverp->port,
						MACH_NOTIFY_NO_SENDERS,
						1,
						serverp->port,
						MACH_MSG_TYPE_MAKE_SEND_ONCE,
						&old_port);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_request_notification");

	/* Add privileged server port to bootstrap port set */
	result = mach_port_move_member(mach_task_self(),
						serverp->port,
						bootstrap_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_move_member");
}

static void
start_server(server_t *serverp)
{
	kern_return_t result;
	mach_port_t old_port;
	int pid;

	/*
	 * Do what's appropriate to get bootstrap port setup in server task
	 */
	switch (serverp->servertype) {

	case MACHINIT:
		break;

	case SERVER:
	case DEMAND:
	case RESTARTABLE:
	  if (!serverp->port)
	      setup_server(serverp);

	  serverp->activity = 0;

	  /* Insert a send right */
	  result = mach_port_insert_right(mach_task_self(),
						serverp->port,
						serverp->port,
						MACH_MSG_TYPE_MAKE_SEND);
	  if (result != KERN_SUCCESS)
	  	kern_fatal(result, "mach_port_insert_right");

		/* Give trusted service a unique bootstrap port */
		result = task_set_bootstrap_port(mach_task_self(),
						 serverp->port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "task_set_bootstrap_port");

		result = mach_port_deallocate(mach_task_self(),
					      serverp->port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_deallocate");

		pid = fork();
		if (pid < 0) {
			unix_error("fork");
		} else if (pid == 0) {	/* CHILD */
			exec_server(serverp);
			exit(1);
		} else {		/* PARENT */

			result = task_set_bootstrap_port(
							mach_task_self(),
							MACH_PORT_NULL);
			if (result != KERN_SUCCESS)
				kern_fatal(result, "task_set_bootstrap_port");

			info("Launched server %x in bootstrap %x uid %d: \"%s\": [pid %d]",
			     serverp->port, serverp->bootstrap->bootstrap_port,
				 serverp->uid, serverp->cmd, pid);
			serverp->pid = pid;
			result = task_for_pid(
							mach_task_self(),
							pid,
							&serverp->task_port);
			if (result != KERN_SUCCESS) {
				kern_error(result, "getting server task port");
				reap_server(serverp);
				dispatch_server(serverp);
				break;
			}
				
			/* Request dead name notification to tell when task dies */
			result = mach_port_request_notification(
							mach_task_self(),
							serverp->task_port,
							MACH_NOTIFY_DEAD_NAME,
							0,
							notify_port,
							MACH_MSG_TYPE_MAKE_SEND_ONCE,
							&old_port);
			if (result != KERN_SUCCESS) {
				kern_error(result, "mach_port_request_notification");
				reap_server(serverp);
				dispatch_server(serverp);
			}
		}
		break;
	}
}

static void
exec_server(server_t *serverp)
{
	char **argv;
	sigset_t mask;

	/*
	 * Setup environment for server, someday this should be Mach stuff
	 * rather than Unix crud
	 */
	argv = argvize(serverp->cmd);
	close_errlog();

	if (serverp->uid != inherited_uid)
		if (setuid(serverp->uid) < 0)
			unix_fatal("Disabled server %x bootstrap %x: \"%s\": setuid(%d)",
					 serverp->port, serverp->bootstrap->bootstrap_port,
					   serverp->cmd, serverp->uid);

	if (setsid() < 0) {
	  	/*
		 * We can't keep this from happening, but we shouldn't start
		 * the server not as a process group leader.  So, just fake like
		 * there was real activity, and exit the child.  If needed,
		 * we'll re-launch it under another pid.
		 */
		serverp->activity = 1;
		unix_fatal("Temporary failure server %x bootstrap %x: \"%s\": setsid()",
			   serverp->port, serverp->bootstrap->bootstrap_port,
			   serverp->cmd);
	}

	sigemptyset(&mask);
	(void) sigprocmask(SIG_SETMASK, &mask, (sigset_t *)NULL);

	execv(argv[0], argv);
	unix_fatal("Disabled server %x bootstrap %x: \"%s\": exec()",
			   serverp->port,
			   serverp->bootstrap->bootstrap_port,
			   serverp->cmd);
}	

static char **
argvize(const char *string)
{
	static char *argv[100], args[1000];
	const char *cp;
	char *argp, term;
	unsigned int nargs;
	
	/*
	 * Convert a command line into an argv for execv
	 */
	nargs = 0;
	argp = args;
	
	for (cp = string; *cp;) {
		while (isspace(*cp))
			cp++;
		term = (*cp == '"') ? *cp++ : '\0';
		if (nargs < NELEM(argv))
			argv[nargs++] = argp;
		while (*cp && (term ? *cp != term : !isspace(*cp))
		 && argp < END_OF(args)) {
			if (*cp == '\\')
				cp++;
			*argp++ = *cp;
			if (*cp)
				cp++;
		}
		*argp++ = '\0';
	}
	argv[nargs] = NULL;
	return argv;
}

static void *
demand_loop(void *arg)
{
	mach_msg_empty_rcv_t dummy;
	kern_return_t dresult;


	for(;;) {
		mach_port_name_array_t members;
		mach_msg_type_number_t membersCnt;
		mach_port_status_t status;
		mach_msg_type_number_t statusCnt;
		unsigned int i;

		/*
		 * Receive indication of message on demand service
		 * ports without actually receiving the message (we'll
		 * let the actual server do that.
		 */
		dresult = mach_msg(
							&dummy.header,
							MACH_RCV_MSG|MACH_RCV_LARGE,
							0,
							0,
							demand_port_set,
							0,
							MACH_PORT_NULL);
		if (dresult != MACH_RCV_TOO_LARGE) {
			kern_error(dresult, "demand_loop: mach_msg()");
			continue;
		}

		/*
		 * If we are shutting down, there is no use processing
		 * any more of these messages.
		 */
		if (shutdown_in_progress == TRUE)
			return arg;	

		/*
		 * Some port(s) now have messages on them, find out
		 * which ones (there is no indication of which port
		 * triggered in the MACH_RCV_TOO_LARGE indication).
		 */
		dresult = mach_port_get_set_status(
							mach_task_self(),
							demand_port_set,
							&members,
							&membersCnt);
		if (dresult != KERN_SUCCESS) {
			kern_error(dresult, "demand_loop: mach_port_get_set_status()");
			continue;
		}

		for (i = 0; i < membersCnt; i++) {
			statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
			dresult = mach_port_get_attributes(
								mach_task_self(),
								members[i],
								MACH_PORT_RECEIVE_STATUS,
								(mach_port_info_t)&status,
								&statusCnt);
			if (dresult != KERN_SUCCESS) {
				kern_error(dresult, "demand_loop: mach_port_get_attributes()");
				continue;
			}

			/*
			 * For each port with messages, take it out of the
			 * demand service portset, and inform the main thread
			 * that it might have to start the server responsible
			 * for it.
			 */
			if (status.mps_msgcount) {
				dresult = mach_port_move_member(
								mach_task_self(),
								members[i],
								MACH_PORT_NULL);
				if (dresult != KERN_SUCCESS) {
					kern_error(dresult, "demand_loop: mach_port_move_member()");
					continue;
				}
				notify_server_loop(members[i]);
			}
		}

		dresult = vm_deallocate(
						mach_task_self(),
						(vm_address_t) members,
						(vm_size_t) membersCnt * sizeof(mach_port_name_t));
		if (dresult != KERN_SUCCESS) {
			kern_error(dresult, "demand_loop: vm_deallocate()");
			continue;
		}
	}
	return NULL;
}
								
/*
 * server_demux -- processes requests off our service port
 * Also handles notifications
 */

static boolean_t
server_demux(
	mach_msg_header_t *Request,
	mach_msg_header_t *Reply)
{
    bootstrap_info_t *bootstrap;
    service_t *servicep;
    server_t *serverp;
    kern_return_t result;
	mig_reply_error_t *reply;
        
	debug("received message on port %x\n", Request->msgh_local_port);

	/*
	 * Do minimal cleanup and then exit.
	 */
	if (shutdown_in_progress == TRUE) {
		notice("Shutting down. Deactivating root bootstrap (%x) ...",
			bootstraps.bootstrap_port);
		deactivate_bootstrap(&bootstraps);
		notice("Done.");
		exit(0);
	}
					
	reply = (mig_reply_error_t *)Reply;

	/*
	 * Pick off notification messages
	 */
	if (Request->msgh_local_port == notify_port) {
		mach_port_name_t np;

		memset(reply, 0, sizeof(*reply));
		switch (Request->msgh_id) {
		case MACH_NOTIFY_DEAD_NAME:
			np = ((mach_dead_name_notification_t *)Request)->not_port;
			debug("Notified dead name %x", np);

			if (np == inherited_bootstrap_port) {
				inherited_bootstrap_port = MACH_PORT_NULL;
				forward_ok = FALSE;
			}
		
			/*
			 * Check to see if a subset requestor port was deleted.
			 */
			while ((bootstrap = lookup_bootstrap_by_req_port(np)) != NULL) {
				debug("Received dead name notification for bootstrap subset %x requestor port %x",
					 bootstrap->bootstrap_port, bootstrap->requestor_port);
				mach_port_deallocate(
									 mach_task_self(),
									 bootstrap->requestor_port);
				bootstrap->requestor_port = MACH_PORT_NULL;
				deactivate_bootstrap(bootstrap);
			}

			/*
			 * Check to see if a defined service has gone
			 * away.
			 */
			while ((servicep = lookup_service_by_port(np)) != NULL) {
				/*
				 * Port gone, registered service died.
				 */
				debug("Received dead name notification for service %s "
					  "on bootstrap port %x\n",
					  servicep->name, servicep->bootstrap);
				debug("Service %s failed - deallocate", servicep->name);
				delete_service(servicep);
			}

			/*
			 * Check to see if a launched server task has gone
			 * away.
			 */
			if ((serverp = lookup_server_by_task_port(np)) != NULL) {
				/*
				 * Port gone, server died or picked up new task.
				 */
				debug("Received task death notification for server %s ",
					  serverp->cmd);
				reap_server(serverp);
				dispatch_server(serverp);
			}

			mach_port_deallocate(mach_task_self(), np);
			reply->RetCode = KERN_SUCCESS;
			break;

		case MACH_NOTIFY_PORT_DELETED:
			np = ((mach_port_deleted_notification_t *)Request)->not_port;
			debug("port deleted notification on 0x%x\n", np);
			reply->RetCode = KERN_SUCCESS;
			break;

		case MACH_NOTIFY_SEND_ONCE:
			debug("notification send-once right went unused\n");
			reply->RetCode = KERN_SUCCESS;
			break;

		default:
			error("Unexpected notification: %d", Request->msgh_id);
			reply->RetCode = KERN_FAILURE;
			break;
		}
	}

	else if (Request->msgh_local_port == backup_port) {
		mach_port_name_t np;

		memset(reply, 0, sizeof(*reply));

		np = ((mach_port_destroyed_notification_t *)Request)->not_port.name; 
		servicep = lookup_service_by_port(np);
		if (servicep != NULL) {
			serverp = servicep->server;

			switch (Request->msgh_id) {

			case MACH_NOTIFY_PORT_DESTROYED:
				/*
				 * Port sent back to us, server died.
				 */
				debug("Received destroyed notification for service %s",
					  servicep->name);
				debug("Service %x bootstrap %x backed up: %s",
				     servicep->port, servicep->bootstrap->bootstrap_port,
					 servicep->name);
				ASSERT(canReceive(servicep->port));
				servicep->isActive = FALSE;
				serverp->active_services--;
				dispatch_server(serverp);
				reply->RetCode = KERN_SUCCESS;
				break;

			case DEMAND_REQUEST:
				/* message reflected over from demand start thread */
				if (!active_server(serverp))
					start_server(serverp);
				reply->RetCode = KERN_SUCCESS;
				break;

			default:
				debug("Mysterious backup_port notification %d", Request->msgh_id);
				reply->RetCode = KERN_FAILURE;
				break;
			}
		} else {
			debug("Backup_port notification - previously deleted service");
			reply->RetCode = KERN_FAILURE;
		}
	}

	else if (Request->msgh_id == MACH_NOTIFY_NO_SENDERS) {
		mach_port_t ns = Request->msgh_local_port;

		if ((serverp = lookup_server_by_port(ns)) != NULL_SERVER) {
	  		/*
			 * A server we launched has released his bootstrap
			 * port send right.  We won't re-launch him unless
			 * his services came back to roost.  But we need to
			 * destroy the bootstrap port for fear of leaking.
			 */
			debug("server %s dropped server port", serverp->cmd);
			serverp->port = MACH_PORT_NULL;
			dispatch_server(serverp);
		} else if ((bootstrap = lookup_bootstrap_by_port(ns)) != NULL) {
			/*
			 * The last direct user of a deactivated bootstrap went away.
			 * We can finally free it.
			 */
			debug("Deallocating bootstrap %x: no more clients", ns);
			bootstrap->bootstrap_port = MACH_PORT_NULL;
			deallocate_bootstrap(bootstrap);
		}
		
		result = mach_port_mod_refs(
						mach_task_self(),
						ns,
						MACH_PORT_RIGHT_RECEIVE,
						-1);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_mod_refs");

		memset(reply, 0, sizeof(*reply));
		reply->RetCode = KERN_SUCCESS;
	}
     
	else {	/* must be a service request */
		debug("Handled request.");
		return bootstrap_server(Request, Reply);
	}
	return TRUE;
}

/*
 * server_loop -- pick requests off our service port and process them
 * Also handles notifications
 */
#define	bootstrapMaxRequestSize	1024
#define	bootstrapMaxReplySize	1024

static void
server_loop(void)
{
	mach_msg_return_t mresult;

	for (;;) {
		mresult = mach_msg_server(
						server_demux,
						bootstrapMaxRequestSize,
						bootstrap_port_set,
                        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SENDER)|
                        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
		if (mresult != MACH_MSG_SUCCESS)
				kern_error(mresult, "mach_msg_server");
	}
}

boolean_t
canReceive(mach_port_t port)
{
	mach_port_type_t p_type;
	kern_return_t result;
	
	result = mach_port_type(mach_task_self(), port, &p_type);
	if (result != KERN_SUCCESS) {
		kern_error(result, "port_type");
		return FALSE;
	}
	return ((p_type & MACH_PORT_TYPE_RECEIVE) != 0);
}


boolean_t
canSend(mach_port_t port)
{
	mach_port_type_t p_type;
	kern_return_t result;
	
	result = mach_port_type(mach_task_self(), port, &p_type);
	if (result != KERN_SUCCESS) {
		kern_error(result, "port_type");
		return FALSE;
	}
	return ((p_type & MACH_PORT_TYPE_PORT_RIGHTS) != 0);
}
