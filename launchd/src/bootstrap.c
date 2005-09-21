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

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/boolean.h>
#include <mach/message.h>
#include <mach/notify.h>
#include <mach/mig_errors.h>
#include <mach/mach_traps.h>
#include <mach/mach_interface.h>
#include <mach/bootstrap.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/exception.h>
#include <servers/bootstrap_defs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libc.h>
#include <paths.h>
#include <syslog.h>
#include <pwd.h>
#include <assert.h>

#include "bootstrap.h"
#include "bootstrapServer.h"
#include "launchd.h"

#define DEMAND_REQUEST   MACH_NOTIFY_LAST	/* demand service messaged */


/* Bootstrap info */
struct bootstrap {
	TAILQ_ENTRY(bootstrap)		tqe;
	struct bootstrap		*parent;
	struct bootstrap		*deactivate;	/* list being deactivated */
	mach_port_name_t		bootstrap_port;
	mach_port_name_t		requestor_port;
	unsigned int			ref_count;
};

struct service {
	TAILQ_ENTRY(service)	tqe;
	mach_port_name_t	port;		/* service port,
					   may have all rights if inactive */
	struct bootstrap	*bootstrap;	/* bootstrap port(s) used at this
					 * level. */
	bool		isActive;	/* server is running */
	struct server		*server;	/* server, declared services only */
	char			name[0];	/* service name */
};

struct server {
	TAILQ_ENTRY(server)	tqe;
	struct bootstrap *bootstrap; /* bootstrap context */
	mach_port_t	port;		/* server's priv bootstrap port */
	mach_port_t	task_port;	/* server's task port */
	uid_t		uid;		/* uid to exec server with */
	pid_t		pid;		/* server's pid */
	int		activity;		/* count of checkins/registers this instance */
	int		active_services;	/* count of active services */
	unsigned int	ondemand:1, __junk:31;
	char		cmd[0];		/* server command to exec */
};

static struct server *server_new(struct bootstrap *bootstrap, const char *cmd, uid_t uid, bool ond);
static void server_delete(struct server *serverp);
static void server_setup(struct server *serverp);
static bool server_active(struct server *serverp);
static bool server_useless(struct server *serverp);
static void server_start(struct server *serverp);
static void server_exec(struct server *serverp);
static void server_reap(struct server *serverp);
static void server_dispatch(struct server *serverp);

static struct server *port_to_server(mach_port_t port);
static struct server *taskport_to_server(mach_port_t port);
static struct service *port_to_service(mach_port_t port);
static struct bootstrap *port_to_bootstrap(mach_port_t port, bool active);
static struct bootstrap *reqport_to_bootstrap(mach_port_t port);

static struct service *service_new(struct bootstrap *bootstrap, const char *name, mach_port_t serviceport, bool isActive, struct server	*serverp);
static void service_delete(struct service *servicep);
static void service_watch(struct service *servicep);

static struct bootstrap *bootstrap_new(struct bootstrap *parent, mach_port_name_t requestorport);
static void bootstrap_delete(struct bootstrap *bootstrap);
static void bootstrap_deactivate(struct bootstrap *bootstrap);
static void bootstrap_delete_services(struct bootstrap *bootstrap);
static struct service *bootstrap_lookup_service(struct bootstrap *bootstrap, const char *name);

static TAILQ_HEAD(bootstrapshead, bootstrap) bootstraps = TAILQ_HEAD_INITIALIZER(bootstraps);
static TAILQ_HEAD(servershead, server) servers = TAILQ_HEAD_INITIALIZER(servers);
static TAILQ_HEAD(serviceshead, service) services = TAILQ_HEAD_INITIALIZER(services);

/* mach_init interposes bootstrap_server() generated by the mig tool with this function */
static boolean_t server_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply);

static mach_port_t inherited_bootstrap_port = MACH_PORT_NULL;
static mach_port_t launchd_bootstrap_port = MACH_PORT_NULL;
static bool forward_ok = true;
static bool mach_init_shutdown_in_progress = false;
static char *register_name = NULL;

static bool canReceive(mach_port_t);

static pid_t fork_with_bootstrap_port(mach_port_t p);
static void init_ports(void);
static char **argvize(const char *string);
static void *demand_loop(void *arg);
static void *mach_server_loop(void *);

/*
 * Private ports we hold receive rights for.  We also hold receive rights
 * for all the privileged ports.  Those are maintained in the server
 * structs.
 */
static mach_port_t bootstrap_port_set;
static mach_port_t demand_port_set;
static pthread_t mach_server_loop_thread;
static pthread_t demand_thread;

static mach_port_t notify_port;
static mach_port_t backup_port;

static mach_msg_return_t inform_server_loop(mach_port_name_t about, mach_msg_option_t options);
static void notify_server_loop(mach_port_name_t about);

void mach_start_shutdown(void)
{
	mach_init_shutdown_in_progress = true;

	inform_server_loop(MACH_PORT_NULL, MACH_SEND_TIMEOUT);
}

void mach_init_init(void)
{
	struct bootstrap *bootstrap;
	kern_return_t result;
	pthread_attr_t attr;

	init_ports();

	if ((bootstrap = bootstrap_new(NULL, MACH_PORT_NULL)) == NULL) {
		syslog(LOG_ALERT, "root bootstrap allocation failed!");
		exit(EXIT_FAILURE);
	}
	
	result = task_get_bootstrap_port(mach_task_self(), &inherited_bootstrap_port);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ALERT, "task_get_bootstrap_port(): %s", mach_error_string(result));
		exit(EXIT_FAILURE);
	}

	if (inherited_bootstrap_port == MACH_PORT_NULL) {
		if (1 != getpid())
			syslog(LOG_NOTICE, "task_get_bootstrap_port() returned MACH_PORT_NULL, not forwarding requests");
		forward_ok = false;
	}

	/* We set this explicitly as we start each child */
	task_set_bootstrap_port(mach_task_self(), MACH_PORT_NULL);

	/* register "self" port with anscestor */		
	if (forward_ok) {
		asprintf(&register_name, "com.apple.launchd.%d", getpid());

		result = bootstrap_register(inherited_bootstrap_port, register_name, bootstrap->bootstrap_port);
		if (result != KERN_SUCCESS)
			panic("register self(): %s", mach_error_string(result));
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	result = pthread_create(&demand_thread, &attr, demand_loop, NULL);
	if (result != 0) {
		syslog(LOG_ERR, "pthread_create(): %s", strerror(result));
		exit(EXIT_FAILURE);
	}

	result = pthread_create(&mach_server_loop_thread, &attr, mach_server_loop, NULL);
	if (result != 0) {
		syslog(LOG_ERR, "pthread_create(): %s", strerror(result));
		exit(EXIT_FAILURE);
	}

	pthread_attr_destroy(&attr);

	launchd_bootstrap_port = bootstrap->bootstrap_port;

	/* cut off the Libc cache, we don't want to deadlock against ourself */
	bootstrap_port = MACH_PORT_NULL;
}

void mach_init_reap(void)
{
	int result;
	void *status;

	result = pthread_join(demand_thread, &status);
	if (result != 0) {
		syslog(LOG_ERR, "pthread_join(): %s", strerror(result));
	}

	result = pthread_join(mach_server_loop_thread, &status);
	if (result != 0) {
		syslog(LOG_ERR, "pthread_join(): %s", strerror(result));
	}
}

void
init_ports(void)
{
	kern_return_t result;

	/* Create port set that server loop listens to */
	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &bootstrap_port_set);
	if (result != KERN_SUCCESS)
		panic("port_set_allocate(): %s", mach_error_string(result));

	/* Create demand port set that second thread listens to */
	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &demand_port_set);
	if (result != KERN_SUCCESS)
		panic("port_set_allocate(): %s", mach_error_string(result));

	/* Create notify port and add to server port set */
	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify_port);
	if (result != KERN_SUCCESS)
		panic("mach_port_allocate(): %s", mach_error_string(result));

	result = mach_port_move_member(mach_task_self(), notify_port, bootstrap_port_set);
	if (result != KERN_SUCCESS)
		panic("mach_port_move_member(): %s", mach_error_string(result));
	
	/* Create backup port and add to server port set */
	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &backup_port);
	if (result != KERN_SUCCESS)
		panic("mach_port_allocate(): %s", mach_error_string(result));

	result = mach_port_move_member(mach_task_self(), backup_port, bootstrap_port_set);
	if (result != KERN_SUCCESS)
		panic("mach_port_move_member(): %s", mach_error_string(result));
}

bool
server_useless(struct server *serverp)
{
	bool server_has_services = false;
	bool active_bstrap = (serverp->bootstrap->requestor_port != MACH_PORT_NULL);
	struct service *servicep;
	
	TAILQ_FOREACH(servicep, &services, tqe) {
	  	if (serverp == servicep->server) {
			server_has_services = true;
			break;
		}
	}

	return (!active_bstrap || !server_has_services || !serverp->activity);
}

bool
server_active(struct server *serverp)
{
	return (serverp->port || serverp->task_port || serverp->active_services);
}

static void
server_reap(struct server *serverp)
{
	kern_return_t result;
	pid_t presult;
	int wstatus;

	presult = waitpid(serverp->pid, &wstatus, WNOHANG);
	switch (presult) {
	case -1:
		syslog(LOG_DEBUG, "waitpid: cmd = %s: %m", serverp->cmd);
		break;

	case 0:
	{
		/* process must have switched mach tasks */
		mach_port_t old_port;

		old_port = serverp->task_port;
		mach_port_deallocate(mach_task_self(), old_port);
		serverp->task_port = MACH_PORT_NULL;

		result = task_for_pid(mach_task_self(), serverp->pid, &serverp->task_port);
		if (result != KERN_SUCCESS) {
			syslog(LOG_INFO, "task_for_pid(%d) race after waitpid(): %s", serverp->pid, mach_error_string(result));
			break;
		}

		/* Request dead name notification to tell when new task dies */
		result = mach_port_request_notification(mach_task_self(), serverp->task_port, MACH_NOTIFY_DEAD_NAME,
				0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &old_port);
		if (result != KERN_SUCCESS) {
			syslog(LOG_INFO, "race setting up notification for new server task port for pid[%d]: %s",
			     serverp->pid, mach_error_string(result));
			break;
		}
		return;
	}

	default:
		if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
			syslog(LOG_NOTICE, "Server %x in bootstrap %x uid %d: \"%s\"[%d]: exited with status: %d",
			       serverp->port, serverp->bootstrap->bootstrap_port,
			       serverp->uid, serverp->cmd, serverp->pid, WEXITSTATUS(wstatus));
		} else if (WIFSIGNALED(wstatus)) {
			syslog(LOG_NOTICE, "Server %x in bootstrap %x uid %d: \"%s\"[%d]: exited abnormally: %s",
			       serverp->port, serverp->bootstrap->bootstrap_port,
			       serverp->uid, serverp->cmd, serverp->pid, strsignal(WTERMSIG(wstatus)));
		}
		break;
	}
		

	serverp->pid = -1;

	/*
	 * Release the server task port reference, if we ever
	 * got it in the first place.
	 */
	if (serverp->task_port != MACH_PORT_NULL) {
		result = mach_port_deallocate(mach_task_self(), serverp->task_port);
		if (result != KERN_SUCCESS)
			syslog(LOG_ERR, "mach_port_deallocate(): %s", mach_error_string(result));
		serverp->task_port = MACH_PORT_NULL;
	}
}

static void
server_demand(struct server *serverp)
{
	struct service *servicep;
	kern_return_t result;

	/*
	 * For on-demand servers, make sure that the service ports are
	 * back in on-demand portset.  Active service ports should come
	 * back through a PORT_DESTROYED notification.  We only have to
	 * worry about the inactive ports that may have been previously
	 * pulled from the set but never checked-in by the server.
	 */

	TAILQ_FOREACH(servicep, &services, tqe) {
		if (serverp == servicep->server && !servicep->isActive) {
			result = mach_port_move_member(mach_task_self(), servicep->port, demand_port_set);
			if (result != KERN_SUCCESS)
				panic("mach_port_move_member(): %s", mach_error_string(result));
		}
	}
}

static void
server_dispatch(struct server *serverp)
{
	if (!server_active(serverp)) {
		if (server_useless(serverp))
			server_delete(serverp);
		else if (serverp->ondemand || mach_init_shutdown_in_progress)
			server_demand(serverp);
		else
			server_start(serverp);
	}
}

void
server_setup(struct server *serverp)
{
	kern_return_t result;
	mach_port_t old_port;
	
	/* Allocate privileged port for requests from service */
	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverp->port);
	syslog(LOG_INFO, "Allocating port %x for server %s", serverp->port, serverp->cmd);
	if (result != KERN_SUCCESS)	
		panic("port_allocate(): %s", mach_error_string(result));

	/* Request no-senders notification so we can tell when server dies */
	result = mach_port_request_notification(mach_task_self(), serverp->port, MACH_NOTIFY_NO_SENDERS,
			1, serverp->port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &old_port);
	if (result != KERN_SUCCESS)
		panic("mach_port_request_notification(): %s", mach_error_string(result));

	/* Add privileged server port to bootstrap port set */
	result = mach_port_move_member(mach_task_self(), serverp->port, bootstrap_port_set);
	if (result != KERN_SUCCESS)
		panic("mach_port_move_member(): %s", mach_error_string(result));
}

pid_t launchd_fork(void)
{
	return fork_with_bootstrap_port(launchd_bootstrap_port);
}

pid_t
fork_with_bootstrap_port(mach_port_t p)
{
	static pthread_mutex_t forklock = PTHREAD_MUTEX_INITIALIZER;
	kern_return_t result;
	pid_t r;
	size_t i;

	pthread_mutex_lock(&forklock);

	sigprocmask(SIG_BLOCK, &blocked_signals, NULL);

	result = task_set_bootstrap_port(mach_task_self(), p);
	if (result != KERN_SUCCESS)
		panic("task_set_bootstrap_port(): %s", mach_error_string(result));

	if (launchd_bootstrap_port != p) {
		result = mach_port_deallocate(mach_task_self(), p);
		if (result != KERN_SUCCESS)
			panic("mach_port_deallocate(): %s", mach_error_string(result));
	}

	r = fork();

	if (r > 0) {
		result = task_set_bootstrap_port(mach_task_self(), MACH_PORT_NULL);
		if (result != KERN_SUCCESS)
			panic("task_set_bootstrap_port(): %s", mach_error_string(result));
	} else if (0 == r) {
		for (i = 0; i <= NSIG; i++) {
			if (sigismember(&blocked_signals, i))
				signal(i, SIG_DFL);
		}
	}

	sigprocmask(SIG_UNBLOCK, &blocked_signals, NULL);
	
	pthread_mutex_unlock(&forklock);

	return r;
}

static void
server_start(struct server *serverp)
{
	kern_return_t result;
	mach_port_t old_port;
	int pid;

	if (!serverp->port)
		server_setup(serverp);

	serverp->activity = 0;

	result = mach_port_insert_right(mach_task_self(),
			serverp->port, serverp->port, MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS)
		panic("mach_port_insert_right(): %s", mach_error_string(result));

	pid = fork_with_bootstrap_port(serverp->port);
	if (pid < 0) {
		syslog(LOG_WARNING, "fork(): %m");
		goto out;
	} else if (pid == 0) {
		server_exec(serverp);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_INFO, "Launched server %x in bootstrap %x uid %d: \"%s\": [pid %d]",
			serverp->port, serverp->bootstrap->bootstrap_port, serverp->uid, serverp->cmd, pid);
	serverp->pid = pid;
	result = task_for_pid(mach_task_self(), pid, &serverp->task_port);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "getting server task port(): %s", mach_error_string(result));
		goto out_bad;
	}
				
	/* Request dead name notification to tell when task dies */
	result = mach_port_request_notification(mach_task_self(),
			serverp->task_port, MACH_NOTIFY_DEAD_NAME, 0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &old_port);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "mach_port_request_notification(): %s", mach_error_string(result));
		goto out_bad;
	}

out:
	return;
out_bad:
	server_reap(serverp);
	server_dispatch(serverp);
}

static void
server_exec(struct server *serverp)
{
	char **argv;
	sigset_t mask;

	argv = argvize(serverp->cmd);
	closelog();

	if (serverp->uid != getuid()) {
		struct passwd *pwd = getpwuid(serverp->uid);
		gid_t g;

		if (NULL == pwd) {
			panic("Disabled server %x bootstrap %x: \"%s\": getpwuid(%d) failed",
				 serverp->port, serverp->bootstrap->bootstrap_port, serverp->cmd, serverp->uid);
		}

		g = pwd->pw_gid;

		if (-1 == setgroups(1, &g)) {
			panic("Disabled server %x bootstrap %x: \"%s\": setgroups(1, %d): %s",
					serverp->port, serverp->bootstrap->bootstrap_port, serverp->cmd, g, strerror(errno));
		}

		if (-1 == setgid(g)) {
			panic("Disabled server %x bootstrap %x: \"%s\": setgid(%d): %s",
					serverp->port, serverp->bootstrap->bootstrap_port, serverp->cmd, g, strerror(errno));
		}

		if (-1 == setuid(serverp->uid)) {
			panic("Disabled server %x bootstrap %x: \"%s\": setuid(%d): %s",
					 serverp->port, serverp->bootstrap->bootstrap_port, serverp->cmd, serverp->uid, strerror(errno));
		}
	}


	if (-1 == setsid()) {
		syslog(LOG_WARNING, "Temporary failure server %x bootstrap %x: \"%s\": setsid(): %s",
			   serverp->port, serverp->bootstrap->bootstrap_port, serverp->cmd, strerror(errno));
	}

	sigemptyset(&mask);
	(void) sigprocmask(SIG_SETMASK, &mask, (sigset_t *)NULL);

	setpriority(PRIO_PROCESS, 0, 0);
	execv(argv[0], argv);
	panic("Disabled server %x bootstrap %x: \"%s\": exec(): %s",
			   serverp->port, serverp->bootstrap->bootstrap_port, serverp->cmd, strerror(errno));
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
		if (nargs < 100)
			argv[nargs++] = argp;
		while (*cp && (term ? *cp != term : !isspace(*cp)) && argp < &args[999]) {
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
demand_loop(void *arg __attribute__((unused)))
{
	mach_msg_empty_rcv_t dummy;
	kern_return_t dresult;


	for (;;) {
		mach_port_name_array_t members;
		mach_msg_type_number_t membersCnt;
		mach_port_status_t status;
		mach_msg_type_number_t statusCnt;
		unsigned int i;

		/*
		 * Receive indication of message on demand service ports
		 * without actually receiving the message (we'll let the actual
		 * server do that.
		 */
		dresult = mach_msg(&dummy.header, MACH_RCV_MSG|MACH_RCV_LARGE, 0, 0, demand_port_set, 0, MACH_PORT_NULL);
		if (dresult == MACH_RCV_PORT_CHANGED) {
			pthread_exit(NULL);
		} else if (dresult != MACH_RCV_TOO_LARGE) {
			syslog(LOG_ERR, "demand_loop: mach_msg(): %s", mach_error_string(dresult));
			continue;
		}

		/*
		 * Some port(s) now have messages on them, find out
		 * which ones (there is no indication of which port
		 * triggered in the MACH_RCV_TOO_LARGE indication).
		 */
		dresult = mach_port_get_set_status(mach_task_self(), demand_port_set, &members, &membersCnt);
		if (dresult != KERN_SUCCESS) {
			syslog(LOG_ERR, "demand_loop: mach_port_get_set_status(): %s", mach_error_string(dresult));
			continue;
		}

		for (i = 0; i < membersCnt; i++) {
			statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
			dresult = mach_port_get_attributes(mach_task_self(), members[i], MACH_PORT_RECEIVE_STATUS,
					(mach_port_info_t)&status, &statusCnt);
			if (dresult != KERN_SUCCESS) {
				syslog(LOG_ERR, "demand_loop: mach_port_get_attributes(): %s", mach_error_string(dresult));
				continue;
			}

			/*
			 * For each port with messages, take it out of the
			 * demand service portset, and inform the main thread
			 * that it might have to start the server responsible
			 * for it.
			 */
			if (status.mps_msgcount) {
				dresult = mach_port_move_member(mach_task_self(), members[i], MACH_PORT_NULL);
				if (dresult != KERN_SUCCESS) {
					syslog(LOG_ERR, "demand_loop: mach_port_move_member(): %s", mach_error_string(dresult));
					continue;
				}
				notify_server_loop(members[i]);
			}
		}

		dresult = vm_deallocate(mach_task_self(), (vm_address_t)members,(vm_size_t) membersCnt * sizeof(mach_port_name_t));
		if (dresult != KERN_SUCCESS) {
			syslog(LOG_ERR, "demand_loop: vm_deallocate(): %s", mach_error_string(dresult));
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
server_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply)
{
	struct bootstrap *bootstrap;
	struct service *servicep;
	struct server *serverp;
	kern_return_t result;
	mig_reply_error_t *reply;

	if (mach_init_shutdown_in_progress) {
		bootstrap_deactivate(TAILQ_FIRST(&bootstraps));
		mach_port_destroy(mach_task_self(), demand_port_set);
		mach_init_shutdown_in_progress = false;
		pthread_exit(NULL);
	}

	syslog(LOG_DEBUG, "received message on port %x", Request->msgh_local_port);

	reply = (mig_reply_error_t *)Reply;

	if (Request->msgh_local_port == notify_port) {
		mach_port_name_t np;

		memset(reply, 0, sizeof(*reply));
		switch (Request->msgh_id) {
		case MACH_NOTIFY_DEAD_NAME:
			np = ((mach_dead_name_notification_t *)Request)->not_port;
			syslog(LOG_DEBUG, "Notified dead name %x", np);

			if (np == inherited_bootstrap_port) {
				inherited_bootstrap_port = MACH_PORT_NULL;
				forward_ok = false;
			}
		
			while ((bootstrap = reqport_to_bootstrap(np))) {
				syslog(LOG_DEBUG, "Received dead name notification for bootstrap subset %x requestor port %x",
					 bootstrap->bootstrap_port, bootstrap->requestor_port);
				mach_port_deallocate(mach_task_self(), bootstrap->requestor_port);
				bootstrap->requestor_port = MACH_PORT_NULL;
				bootstrap_deactivate(bootstrap);
			}

			while ((servicep = port_to_service(np))) {
				syslog(LOG_DEBUG, "Received dead name notification for service %s on bootstrap port %x\n",
					  servicep->name, servicep->bootstrap);
				syslog(LOG_DEBUG, "Service %s failed - deallocate", servicep->name);
				service_delete(servicep);
			}

			if ((serverp = taskport_to_server(np)) != NULL) {
				syslog(LOG_DEBUG, "Received task death notification for server %s", serverp->cmd);
				server_reap(serverp);
				server_dispatch(serverp);
			}

			mach_port_deallocate(mach_task_self(), np);
			reply->RetCode = KERN_SUCCESS;
			break;
		case MACH_NOTIFY_PORT_DELETED:
			np = ((mach_port_deleted_notification_t *)Request)->not_port;
			syslog(LOG_DEBUG, "port deleted notification on 0x%x", np);
			reply->RetCode = KERN_SUCCESS;
			break;
		case MACH_NOTIFY_SEND_ONCE:
			syslog(LOG_DEBUG, "notification send-once right went unused");
			reply->RetCode = KERN_SUCCESS;
			break;
		default:
			syslog(LOG_ERR, "Unexpected notification: %d", Request->msgh_id);
			reply->RetCode = KERN_FAILURE;
			break;
		}
	} else if (Request->msgh_local_port == backup_port) {
		mach_port_name_t np;

		memset(reply, 0, sizeof(*reply));

		np = ((mach_port_destroyed_notification_t *)Request)->not_port.name; 
		servicep = port_to_service(np);
		if (servicep != NULL) {
			serverp = servicep->server;

			switch (Request->msgh_id) {
			case MACH_NOTIFY_PORT_DESTROYED:
				/*
				 * Port sent back to us, server died.
				 */
				syslog(LOG_DEBUG, "Received destroyed notification for service %s", servicep->name);
				syslog(LOG_DEBUG, "Service %x bootstrap %x backed up: %s",
				     servicep->port, servicep->bootstrap->bootstrap_port, servicep->name);
				assert(canReceive(servicep->port));
				servicep->isActive = false;
				serverp->active_services--;
				server_dispatch(serverp);
				reply->RetCode = KERN_SUCCESS;
				break;
			case DEMAND_REQUEST:
				/* message reflected over from demand start thread */
				if (!server_active(serverp))
					server_start(serverp);
				reply->RetCode = KERN_SUCCESS;
				break;
			default:
				syslog(LOG_DEBUG, "Mysterious backup_port notification %d", Request->msgh_id);
				reply->RetCode = KERN_FAILURE;
				break;
			}
		} else {
			syslog(LOG_DEBUG, "Backup_port notification - previously deleted service");
			reply->RetCode = KERN_FAILURE;
		}
	} else if (Request->msgh_id == MACH_NOTIFY_NO_SENDERS) {
		mach_port_t ns = Request->msgh_local_port;

		if ((serverp = port_to_server(ns)) != NULL) {
	  		/*
			 * A server we launched has released his bootstrap
			 * port send right.  We won't re-launch him unless
			 * his services came back to roost.  But we need to
			 * destroy the bootstrap port for fear of leaking.
			 */
			syslog(LOG_DEBUG, "server %s dropped server port", serverp->cmd);
			serverp->port = MACH_PORT_NULL;
			server_dispatch(serverp);
		} else if ((bootstrap = port_to_bootstrap(ns, false)) != NULL) {
			/*
			 * The last direct user of a deactivated bootstrap went away.
			 * We can finally free it.
			 */
			syslog(LOG_DEBUG, "Deallocating bootstrap %x: no more clients", ns);
			bootstrap->bootstrap_port = MACH_PORT_NULL;
			bootstrap_delete(bootstrap);
		}
		
		result = mach_port_mod_refs(mach_task_self(), ns, MACH_PORT_RIGHT_RECEIVE, -1);
		if (result != KERN_SUCCESS)
			panic("mach_port_mod_refs(): %s", mach_error_string(result));

		memset(reply, 0, sizeof(*reply));
		reply->RetCode = KERN_SUCCESS;
	} else {
		/* must be a service request */
		syslog(LOG_DEBUG, "Handled request.");
		return bootstrap_server(Request, Reply);
	}
	return true;
}

/*
 * server_loop -- pick requests off our service port and process them
 * Also handles notifications
 */
union bootstrapMaxRequestSize {
	union __RequestUnion__x_bootstrap_subsystem req;
	union __ReplyUnion__x_bootstrap_subsystem rep;
};

void *
mach_server_loop(void *arg __attribute__((unused)))
{
	mach_msg_return_t mresult;

	for (;;) {
		mresult = mach_msg_server(server_demux, sizeof(union bootstrapMaxRequestSize), bootstrap_port_set,
				MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SENDER)|MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
		if (mresult != MACH_MSG_SUCCESS)
				syslog(LOG_ERR, "mach_msg_server(): %s", mach_error_string(mresult));
	}
	return NULL;
}

bool
canReceive(mach_port_t port)
{
	mach_port_type_t p_type;
	kern_return_t result;
	
	result = mach_port_type(mach_task_self(), port, &p_type);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "port_type(): %s", mach_error_string(result));
		return false;
	}
	return ((p_type & MACH_PORT_TYPE_RECEIVE) != 0);
}


struct server *
server_new(struct bootstrap *bootstrap, const char *cmd, uid_t uid, bool ond)
{
	struct server *serverp;

	syslog(LOG_DEBUG, "adding new server \"%s\" with uid %d", cmd, uid);	
	serverp = calloc(1, sizeof(struct server) + strlen(cmd) + 1);

	if (NULL == serverp)
		goto out;

	TAILQ_INSERT_TAIL(&servers, serverp, tqe);

	bootstrap->ref_count++;
	serverp->bootstrap = bootstrap;

	serverp->pid = -1;
	serverp->uid = uid;

	serverp->ondemand = ond;
	strcpy(serverp->cmd, cmd);

out:
	return serverp;
}
	
struct service *
service_new(struct bootstrap *bootstrap, const char *name, mach_port_t serviceport, bool isActive, struct server *serverp)
{
	struct service *servicep;

	if ((servicep = calloc(1, sizeof(struct service) + strlen(name) + 1)) == NULL)
		goto out;

	TAILQ_INSERT_TAIL(&services, servicep, tqe);
	
	strcpy(servicep->name, name);
	servicep->bootstrap = bootstrap;
	servicep->port = serviceport;
	servicep->server = serverp;
	servicep->isActive = isActive;

out:
	if (servicep)
		syslog(LOG_INFO, "Created new service %x in bootstrap %x: %s", servicep->port, bootstrap->bootstrap_port, name);

	return servicep;
}

struct bootstrap *
bootstrap_new(struct bootstrap *parent, mach_port_t requestorport)
{
	struct bootstrap *bootstrap;
	kern_return_t result;

	if ((bootstrap = calloc(1, sizeof(struct bootstrap))) == NULL)
		goto out_bad;

	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &bootstrap->bootstrap_port);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "mach_port_allocate(): %s", mach_error_string(result));
		goto out_bad;
	}

	result = mach_port_insert_right(mach_task_self(), bootstrap->bootstrap_port,
			bootstrap->bootstrap_port, MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "failed to insert send right(): %s", mach_error_string(result));
		goto out_bad;
	}

	result = mach_port_insert_member(mach_task_self(), bootstrap->bootstrap_port, bootstrap_port_set);
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "port_set_add(): %s", mach_error_string(result));
		goto out_bad;
	}

	TAILQ_INSERT_TAIL(&bootstraps, bootstrap, tqe);
	
	if (requestorport != MACH_PORT_NULL) {
		bootstrap->requestor_port = requestorport;
	} else {
		bootstrap->requestor_port = bootstrap->bootstrap_port;
	}

	bootstrap->ref_count = 1;

	if (parent) {
		bootstrap->parent = parent;
		parent->ref_count++;
	} else {
		bootstrap->ref_count = 2;
	}

	return bootstrap;

out_bad:
	if (bootstrap) {
		if (bootstrap->bootstrap_port != MACH_PORT_NULL)
			mach_port_deallocate(mach_task_self(), bootstrap->bootstrap_port);
		free(bootstrap);
	}
	return NULL;
}

struct bootstrap *
port_to_bootstrap(mach_port_t port, bool active)
{
	struct bootstrap *bootstrap = NULL;
	struct server *serverp;

	TAILQ_FOREACH(bootstrap, &bootstraps, tqe) {  
		if (bootstrap->bootstrap_port == port)
			goto out;
	}
	
	TAILQ_FOREACH(serverp, &servers, tqe) {
	  	if (port == serverp->port) {
			bootstrap = serverp->bootstrap;
			goto out;
		}
	}

out:
	if (bootstrap && active && bootstrap->requestor_port == MACH_PORT_NULL)
		bootstrap = NULL;
	return bootstrap;
}

struct bootstrap *
reqport_to_bootstrap(mach_port_t port)
{
	struct bootstrap *bootstrap;

	TAILQ_FOREACH(bootstrap, &bootstraps, tqe) {
		if (bootstrap->requestor_port == port)
			return bootstrap;
	}

	return NULL;
}

struct service *
bootstrap_lookup_service(struct bootstrap *bootstrap, const char *name)
{
	struct service *servicep = NULL;

	for (; bootstrap; bootstrap = bootstrap->parent) {
		TAILQ_FOREACH(servicep, &services, tqe) {
			if (servicep->bootstrap != bootstrap)
				continue;
			if (0 != strcmp(name, servicep->name))
				continue;
			goto out;
		}
	}

out:
	return servicep;
}

void
service_delete(struct service *servicep)
{
	TAILQ_REMOVE(&services, servicep, tqe);

	if (servicep->server) {
		syslog(LOG_INFO, "Declared service %s now unavailable", servicep->name);
		mach_port_deallocate(mach_task_self(), servicep->port);
		mach_port_mod_refs(mach_task_self(), servicep->port, MACH_PORT_RIGHT_RECEIVE, -1);
	} else {
		syslog(LOG_INFO, "Registered service %s deleted", servicep->name);
		mach_port_deallocate(mach_task_self(), servicep->port);
	}
	free(servicep);
}

void
service_watch(struct service *servicep)
{
	kern_return_t result;
	mach_port_t previous;

	servicep->isActive = true;

	if (servicep->server) {
		/* registered server - service needs backup */
		servicep->server->activity++;
		servicep->server->active_services++;
		result = mach_port_request_notification(mach_task_self(), servicep->port, MACH_NOTIFY_PORT_DESTROYED,
				0, backup_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
		if (result != KERN_SUCCESS)
			panic("mach_port_request_notification(): %s", mach_error_string(result));
	} else {
		/* one time use/created service */
		result = mach_port_request_notification(mach_task_self(), servicep->port, MACH_NOTIFY_DEAD_NAME,
				0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
		if (result != KERN_SUCCESS) {
			//should service_delete(servicep) instead of panic()
			panic("mach_port_request_notification(): %s", mach_error_string(result));
		} else if (previous != MACH_PORT_NULL) {
			syslog(LOG_DEBUG, "deallocating old notification port (%x) for checked in service %x",
				previous, servicep->port);
			result = mach_port_deallocate(mach_task_self(), previous);
			if (result != KERN_SUCCESS)
				panic("mach_port_deallocate(): %s", mach_error_string(result));
		}
	}
}

static void
bootstrap_delete_services(struct bootstrap *bootstrap)
{
	struct server  *serverp;
	struct service *servicep;
	struct service *next;
	
	for (servicep = TAILQ_FIRST(&services); servicep; servicep = next) {
		next = TAILQ_NEXT(servicep, tqe);
	  	if (bootstrap != servicep->bootstrap)
			continue;

		serverp = servicep->server;

		if (servicep->isActive && serverp)
			serverp->active_services--;

		service_delete(servicep);

		if (!serverp)
			continue;

		if (!server_active(serverp))
			server_delete(serverp);
	}
}

static struct service *
port_to_service(mach_port_t port)
{
	struct service *servicep;
	
	TAILQ_FOREACH(servicep, &services, tqe) {
	  	if (port == servicep->port)
			return servicep;
	}
	return NULL;
}

static struct server *
taskport_to_server(mach_port_t port)
{
	struct server *serverp;
	
	TAILQ_FOREACH(serverp, &servers, tqe) {
	  	if (port == serverp->task_port)
			return serverp;
	}
	return NULL;
}

static struct server *
port_to_server(mach_port_t port)
{
	struct server *serverp;
	
	TAILQ_FOREACH(serverp, &servers, tqe) {
	  	if (port == serverp->port)
			return serverp;
	}
	return NULL;
}

static void
server_delete(struct server *serverp)
{
	struct service *servicep;
	struct service *next;

	syslog(LOG_INFO, "Deleting server %s", serverp->cmd);

	TAILQ_REMOVE(&servers, serverp, tqe);

	for (servicep = TAILQ_FIRST(&services); servicep; servicep = next)
	{
		next = TAILQ_NEXT(servicep, tqe);
	  	if (serverp == servicep->server)
			service_delete(servicep);
	}

	bootstrap_delete(serverp->bootstrap);

	if (serverp->port)
		mach_port_mod_refs(mach_task_self(), serverp->port, MACH_PORT_RIGHT_RECEIVE, -1);

	free(serverp);
}	

void
bootstrap_deactivate(struct bootstrap *bootstrap)
{
	struct bootstrap *deactivating_bootstraps;
	struct bootstrap *query_bootstrap;
	struct bootstrap *next_limit;
	struct bootstrap *limit;

	/*
	 * we need to recursively deactivate the whole subset tree below
	 * this point.  But we don't want to do real recursion because
	 * we don't have a limit on the depth.  So, build up a chain of
	 * active bootstraps anywhere underneath this one.
	 */
	deactivating_bootstraps = bootstrap;
	bootstrap->deactivate = NULL;
	for (next_limit = deactivating_bootstraps, limit = NULL; deactivating_bootstraps != limit;
			limit = next_limit, next_limit = deactivating_bootstraps)
	{
		for (bootstrap = deactivating_bootstraps; bootstrap != limit; bootstrap = bootstrap->deactivate)
		{
			TAILQ_FOREACH(query_bootstrap, &bootstraps, tqe) {
				if (query_bootstrap->parent == bootstrap &&
					query_bootstrap->requestor_port != MACH_PORT_NULL) {
					mach_port_deallocate(mach_task_self(), query_bootstrap->requestor_port);
					query_bootstrap->requestor_port = MACH_PORT_NULL;
					query_bootstrap->deactivate = deactivating_bootstraps;
					deactivating_bootstraps = query_bootstrap;
				}
			}
		}
	}

	/*
	 * The list is ordered with the furthest away progeny being
	 * at the front, and concluding with the one we started with.
	 * This allows us to safely deactivate and remove the reference
	 * each holds on their parent without fear of the chain getting
	 * corrupted (because each active parent holds a reference on
	 * itself and that doesn't get removed until we reach its spot
	 * in the list).
	 */
	do {
		mach_port_t previous;

		bootstrap = deactivating_bootstraps;
		deactivating_bootstraps = bootstrap->deactivate;

		syslog(LOG_INFO, "deactivating bootstrap %x", bootstrap->bootstrap_port);

		bootstrap_delete_services(bootstrap);
		
		mach_port_deallocate(mach_task_self(), bootstrap->bootstrap_port);

		mach_port_request_notification( mach_task_self(), bootstrap->bootstrap_port, MACH_NOTIFY_NO_SENDERS,
				1, bootstrap->bootstrap_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
	} while (deactivating_bootstraps != NULL);
}

void
bootstrap_delete(struct bootstrap *bootstrap)
{
	struct bootstrap *parent = bootstrap->parent;

	if (--bootstrap->ref_count > 0)
		return;

	TAILQ_REMOVE(&bootstraps, bootstrap, tqe);
	free(bootstrap);

	if (parent)
		bootstrap_delete(parent);
}

#define bsstatus(servicep) \
	(((servicep)->isActive) ? BOOTSTRAP_STATUS_ACTIVE : \
	 (((servicep)->server && (servicep)->server->ondemand) ? \
		BOOTSTRAP_STATUS_ON_DEMAND : BOOTSTRAP_STATUS_INACTIVE))

/*
 * kern_return_t
 * bootstrap_create_server(mach_port_t bootstrap_port,
 *	 cmd_t server_cmd,
 *	 integer_t server_uid,
 *	 bool on_demand,
 *	 mach_port_t *server_portp)
 *
 * Returns send rights to server_port of service.  At this point, the
 * server appears active, so nothing will try to launch it.  The server_port
 * can be used to delare services associated with this server by calling
 * bootstrap_create_service() and passing server_port as the bootstrap port.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_NOT_PRIVILEGED, if bootstrap port invalid.
 */
__private_extern__ kern_return_t
x_bootstrap_create_server(mach_port_t bootstrapport, cmd_t server_cmd, uid_t server_uid, boolean_t on_demand,
		security_token_t sectoken, mach_port_t *server_portp)
{
	struct server *serverp;
	struct bootstrap *bootstrap;

	uid_t client_euid = sectoken.val[0];

	bootstrap = port_to_bootstrap(bootstrapport, true);
	syslog(LOG_DEBUG, "Server create attempt: \"%s\" bootstrap %x", server_cmd, bootstrapport);

	/* No forwarding allowed for this call - security risk */
	if (!bootstrap) {
		syslog(LOG_DEBUG, "Server create: \"%s\": invalid bootstrap %x", server_cmd, bootstrapport);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (client_euid != 0 && client_euid != getuid()) {
		syslog(LOG_NOTICE, "Server create: \"%s\": insufficient privilege: The caller is UID %d and we're %d",
			server_cmd, client_euid, getuid());
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (getuid() != 0 && server_uid != getuid()) {
		syslog(LOG_WARNING, "Server create: \"%s\": As UID %d, we will not be able to switch to UID %d",
			server_cmd, getuid(), server_uid);
		server_uid = getuid();
	}

	serverp = server_new(bootstrap, server_cmd, server_uid, on_demand);
	server_setup(serverp);

	syslog(LOG_INFO, "New server %x in bootstrap %x: \"%s\"", serverp->port, bootstrapport, server_cmd);
	*server_portp = serverp->port;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_unprivileged(mach_port_t bootstrapport,
 *			  mach_port_t *unprivportp)
 *
 * Given a bootstrap port, return its unprivileged equivalent.  If
 * the port is already unprivileged, another reference to the same
 * port is returned.
 *
 * This is most often used by servers, which are launched with their
 * bootstrap port set to the privileged port for the server, to get
 * an unprivileged version of the same port for use by its unprivileged
 * children (or any offspring that it does not want to count as part
 * of the "server" for mach_init registration and re-launch purposes).
 */
__private_extern__ kern_return_t
x_bootstrap_unprivileged(mach_port_t bootstrapport, mach_port_t *unprivportp)
{
	struct bootstrap *bootstrap;

	syslog(LOG_DEBUG, "Get unprivileged attempt for bootstrap %x", bootstrapport);

	bootstrap = port_to_bootstrap(bootstrapport, true);
	if (!bootstrap) {
		syslog(LOG_DEBUG, "Get unprivileged: invalid bootstrap %x", bootstrapport);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	*unprivportp = bootstrap->bootstrap_port;

	syslog(LOG_DEBUG, "Get unpriv bootstrap %x returned for bootstrap %x", bootstrap->bootstrap_port, bootstrapport);
	return BOOTSTRAP_SUCCESS;
}

  
/*
 * kern_return_t
 * bootstrap_check_in(mach_port_t bootstrapport,
 *	 name_t servicename,
 *	 mach_port_t *serviceportp)
 *
 * Returns receive rights to service_port of service named by service_name.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_UNKNOWN_SERVICE, if service does not exist.
 *		Returns BOOTSTRAP_SERVICE_NOT_DECLARED, if service not declared
 *			in /etc/bootstrap.conf.
 *		Returns BOOTSTRAP_SERVICE_ACTIVE, if service has already been
 *			registered or checked-in.
 */
__private_extern__ kern_return_t
x_bootstrap_check_in(mach_port_t bootstrapport, name_t servicename, mach_port_t *serviceportp)
{
	kern_return_t result;
	struct service *servicep;
	struct server *serverp;
	struct bootstrap *bootstrap;

	serverp = port_to_server(bootstrapport);
	bootstrap = port_to_bootstrap(bootstrapport, true);
	syslog(LOG_DEBUG, "Service checkin attempt for service %s bootstrap %x", servicename, bootstrapport);

	servicep = bootstrap_lookup_service(bootstrap, servicename);
	if (servicep == NULL || servicep->port == MACH_PORT_NULL) {
		syslog(LOG_DEBUG, "bootstrap_check_in service %s unknown%s", servicename, forward_ok ? " forwarding" : "");
		result = BOOTSTRAP_UNKNOWN_SERVICE;
		if (forward_ok)
			result = bootstrap_check_in(inherited_bootstrap_port, servicename, serviceportp);
		return result;
	}
	if (servicep->server != NULL && servicep->server != serverp) {
		syslog(LOG_DEBUG, "bootstrap_check_in service %s not privileged", servicename);
		 return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (!canReceive(servicep->port)) {
		assert(servicep->isActive);
		syslog(LOG_DEBUG, "bootstrap_check_in service %s already active", servicename);
		return BOOTSTRAP_SERVICE_ACTIVE;
	}

	service_watch(servicep);

	syslog(LOG_INFO, "Checkin service %x in bootstrap %x: %s", servicep->port, servicep->bootstrap->bootstrap_port, servicep->name);

	*serviceportp = servicep->port;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_register(mach_port_t bootstrapport,
 *	name_t servicename,
 *	mach_port_t serviceport)
 *
 * Registers send rights for the port service_port for the service named by
 * service_name.  Registering a declared service or registering a service for
 * which bootstrap has receive rights via a port backup notification is
 * allowed.
 * The previous service port will be deallocated.  Restarting services wishing
 * to resume service for previous clients must first attempt to checkin to the
 * service.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_NOT_PRIVILEGED, if request directed to
 *			unprivileged bootstrap port.
 *		Returns BOOTSTRAP_SERVICE_ACTIVE, if service has already been
 *			register or checked-in.
 */
__private_extern__ kern_return_t
x_bootstrap_register(mach_port_t bootstrapport, name_t servicename, mach_port_t serviceport)
{
	struct service *servicep;
	struct server *serverp;
	struct bootstrap *bootstrap;

	syslog(LOG_DEBUG, "Register attempt for service %s port %x", servicename, serviceport);

	bootstrap = port_to_bootstrap(bootstrapport, true);
	if (!bootstrap)
		return BOOTSTRAP_NOT_PRIVILEGED;
	  
	/*
	 * If this bootstrap port is for a server, or it's an unprivileged
	 * bootstrap can't register the port.
	 */
	serverp = port_to_server(bootstrapport);
	servicep = bootstrap_lookup_service(bootstrap, servicename);
	if (servicep && servicep->server && servicep->server != serverp)
		return BOOTSTRAP_NOT_PRIVILEGED;

	if (servicep && servicep->bootstrap == bootstrap) {
		if (servicep->isActive) {
			syslog(LOG_DEBUG, "Register: service %s already active, port %x", servicep->name, servicep->port);
			assert(!canReceive(servicep->port));
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		if (servicep->server)
			serverp->activity++;
		service_delete(servicep);
	}
	servicep = service_new(bootstrap, servicename, serviceport, true, NULL);

	service_watch(servicep);

	syslog(LOG_INFO, "Registered service %x bootstrap %x: %s", servicep->port, servicep->bootstrap->bootstrap_port, servicep->name);

	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_look_up(mach_port_t bootstrapport,
 *	name_t servicename,
 *	mach_port_t *serviceportp)
 *
 * Returns send rights for the service port of the service named by
 * service_name in *service_portp.  Service is not guaranteed to be active.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_UNKNOWN_SERVICE, if service does not exist.
 */
__private_extern__ kern_return_t
x_bootstrap_look_up(mach_port_t bootstrapport, name_t servicename, mach_port_t *serviceportp)
{
	struct service *servicep;
	struct bootstrap *bootstrap;

	bootstrap = port_to_bootstrap(bootstrapport, true);
	servicep = bootstrap_lookup_service(bootstrap, servicename);
	if (servicep == NULL || servicep->port == MACH_PORT_NULL) {
		if (forward_ok) {
			syslog(LOG_DEBUG, "bootstrap_look_up service %s forwarding", servicename);
			return bootstrap_look_up(inherited_bootstrap_port, servicename, serviceportp);
		} else {
			syslog(LOG_DEBUG, "bootstrap_look_up service %s unknown", servicename);
			return BOOTSTRAP_UNKNOWN_SERVICE;
		}
	}
	*serviceportp = servicep->port;
	syslog(LOG_DEBUG, "Lookup returns port %x for service %s", servicep->port, servicep->name);
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_look_up_array(mach_port_t bootstrapport,
 *	name_array_t	servicenames,
 *	int		servicenames_cnt,
 *	mach_port_array_t	*serviceports,
 *	int		*serviceports_cnt,
 *	bool	*allservices_known)
 *
 * Returns port send rights in corresponding entries of the array service_ports
 * for all services named in the array service_names.  Service_ports_cnt is
 * returned and will always equal service_names_cnt (assuming service_names_cnt
 * is greater than or equal to zero).
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_NO_MEMORY, if server couldn't obtain memory
 *			for response.
 *		Unknown service names have the corresponding service
 *			port set to MACH_PORT_NULL.
 *		If all services are known, all_services_known is true on
 *			return,
 *		if any service is unknown, it's false.
 */
__private_extern__ kern_return_t
x_bootstrap_look_up_array(mach_port_t bootstrapport, name_array_t servicenames, unsigned int servicenames_cnt,
		mach_port_array_t *serviceportsp, unsigned int *serviceports_cnt, boolean_t *allservices_known)
{
	unsigned int i;
	static mach_port_t service_ports[BOOTSTRAP_MAX_LOOKUP_COUNT];
	
	if (servicenames_cnt > BOOTSTRAP_MAX_LOOKUP_COUNT)
		return BOOTSTRAP_BAD_COUNT;
	*serviceports_cnt = servicenames_cnt;
	*allservices_known = true;
	for (i = 0; i < servicenames_cnt; i++) {
		if (x_bootstrap_look_up(bootstrapport, servicenames[i], &service_ports[i]) != BOOTSTRAP_SUCCESS) {
			*allservices_known = false;
			service_ports[i] = MACH_PORT_NULL;
		}
	}
	syslog(LOG_DEBUG, "bootstrap_look_up_array returns %d ports", servicenames_cnt);
	*serviceportsp = service_ports;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_parent(mach_port_t bootstrapport,
 *		    mach_port_t *parentport);
 *
 * Given a bootstrap subset port, return the parent bootstrap port.
 * If the specified bootstrap port is already the root subset, we
 * return the port again. This is a bug. It should return
 * MACH_PORT_NULL, but now we're locked in since apps expect this 
 * behavior. Sigh...
 *
 *
 * Errors:
 *	Returns BOOTSTRAP_NOT_PRIVILEGED if the caller is not running
 *	with an effective user id of root (as determined by the security
 *	token in the message trailer).
 */
__private_extern__ kern_return_t
x_bootstrap_parent(mach_port_t bootstrapport, security_token_t sectoken, mach_port_t *parentport)
{
	struct bootstrap *bootstrap;
	uid_t u = sectoken.val[0];

	syslog(LOG_DEBUG, "Parent attempt for bootstrap %x", bootstrapport);

	bootstrap = port_to_bootstrap(bootstrapport, true);
	if (!bootstrap) { 
		syslog(LOG_DEBUG, "Parent attempt for bootstrap %x: invalid bootstrap", bootstrapport);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (u) {
		syslog(LOG_NOTICE, "UID %d was denied an answer to bootstrap_parent().", u);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (bootstrap->parent) {
		*parentport = bootstrap->parent->bootstrap_port;
	} else if (MACH_PORT_NULL != inherited_bootstrap_port) {
		*parentport = inherited_bootstrap_port;
	} else {
		*parentport = bootstrap->bootstrap_port;
	}
	syslog(LOG_DEBUG, "Returning bootstrap parent %x for bootstrap %x", *parentport, bootstrapport);
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_status(mach_port_t bootstrapport,
 *	name_t servicename,
 *	bootstrap_status_t *serviceactive);
 *
 * Returns: service_active indicates if service is available.
 *			
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_UNKNOWN_SERVICE, if service does not exist.
 */
__private_extern__ kern_return_t
x_bootstrap_status(mach_port_t bootstrapport, name_t servicename, bootstrap_status_t *serviceactivep)
{
	struct service *servicep;
	struct bootstrap *bootstrap;

	bootstrap = port_to_bootstrap(bootstrapport, true);
	servicep = bootstrap_lookup_service(bootstrap, servicename);
	if (servicep == NULL) {
		if (forward_ok) {
			syslog(LOG_DEBUG, "bootstrap_status forwarding status, server %s", servicename);
			return bootstrap_status(inherited_bootstrap_port, servicename, serviceactivep);
		} else {
			syslog(LOG_DEBUG, "bootstrap_status service %s unknown", servicename);
			return BOOTSTRAP_UNKNOWN_SERVICE;
		}
	}
	*serviceactivep = bsstatus(servicep);

	syslog(LOG_DEBUG, "bootstrap_status server %s %sactive", servicename, servicep->isActive ? "" : "in");
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_info(mach_port_t bootstrapport,
 *	name_array_t *servicenamesp,
 *	int *servicenames_cnt,
 *	name_array_t *servernamesp,
 *	int *servernames_cnt,
 *	bootstrap_status_array_t *serviceactivesp,
 *	int *serviceactive_cnt);
 *
 * Returns bootstrap status for all known services.
 *			
 * Errors:	Returns appropriate kernel errors on rpc failure.
 */
__private_extern__ kern_return_t
x_bootstrap_info(mach_port_t bootstrapport, name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		name_array_t *servernamesp, unsigned int *servernames_cnt,
		bootstrap_status_array_t *serviceactivesp, unsigned int *serviceactives_cnt)
{
	kern_return_t result;
	unsigned int i, cnt;
	struct service *servicep;
	struct server *serverp;
	struct bootstrap *bootstrap;
	name_array_t service_names;
	name_array_t server_names;
	bootstrap_status_array_t service_actives;

	bootstrap = port_to_bootstrap(bootstrapport, true);

	cnt = 0;
	TAILQ_FOREACH(servicep, &services, tqe) {
	    if (bootstrap_lookup_service(bootstrap, servicep->name) == servicep)
	    	cnt++;
	}
	result = vm_allocate(mach_task_self(), (vm_address_t *)&service_names, cnt * sizeof(service_names[0]), true);
	if (result != KERN_SUCCESS)
		return BOOTSTRAP_NO_MEMORY;

	result = vm_allocate(mach_task_self(), (vm_address_t *)&server_names, cnt * sizeof(server_names[0]), true);
	if (result != KERN_SUCCESS) {
		(void)vm_deallocate(mach_task_self(), (vm_address_t)service_names, cnt * sizeof(service_names[0]));
		return BOOTSTRAP_NO_MEMORY;
	}
	result = vm_allocate(mach_task_self(), (vm_address_t *)&service_actives, cnt * sizeof(service_actives[0]), true);
	if (result != KERN_SUCCESS) {
		(void)vm_deallocate(mach_task_self(), (vm_address_t)service_names, cnt * sizeof(service_names[0]));
		(void)vm_deallocate(mach_task_self(), (vm_address_t)server_names, cnt * sizeof(server_names[0]));
		return BOOTSTRAP_NO_MEMORY;
	}

	i = 0;
	TAILQ_FOREACH(servicep, &services, tqe) {
	    if (bootstrap_lookup_service(bootstrap, servicep->name) != servicep)
		continue;
	    strncpy(service_names[i], servicep->name, sizeof(service_names[0]));
	    service_names[i][sizeof(service_names[0]) - 1] = '\0';
	    if (servicep->server) {
		    serverp = servicep->server;
		    strncpy(server_names[i], serverp->cmd, sizeof(server_names[0]));
		    server_names[i][sizeof(server_names[0]) - 1] = '\0';
		    syslog(LOG_DEBUG, "bootstrap info service %s server %s %sactive", servicep->name, serverp->cmd,
				    servicep->isActive ? "" : "in"); 
	    } else {
		    server_names[i][0] = '\0';
		    syslog(LOG_DEBUG, "bootstrap info service %s %sactive", servicep->name, servicep->isActive ? "" : "in"); 
	    }
	    service_actives[i] = bsstatus(servicep);
	    i++;
	}
	*servicenamesp = service_names;
	*servernamesp = server_names;
	*serviceactivesp = service_actives;
	*servicenames_cnt = *servernames_cnt = *serviceactives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_subset(mach_port_t bootstrapport,
 *		    mach_port_t requestorport,
 *		    mach_port_t *subsetport);
 *
 * Returns a new port to use as a bootstrap port.  This port behaves
 * exactly like the previous bootstrap_port, except that ports dynamically
 * registered via bootstrap_register() are available only to users of this
 * specific subset_port.  Lookups on the subset_port will return ports
 * registered with this port specifically, and ports registered with
 * ancestors of this subset_port.  Duplications of services already
 * registered with an ancestor port may be registered with the subset port
 * are allowed.  Services already advertised may then be effectively removed
 * by registering MACH_PORT_NULL for the service.
 * When it is detected that the requestor_port is destroyed the subset
 * port and all services advertized by it are destroyed as well.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 */
__private_extern__ kern_return_t
x_bootstrap_subset(mach_port_t bootstrapport, mach_port_t requestorport, mach_port_t *subsetportp)
{
	kern_return_t result;
	struct bootstrap *bootstrap;
	struct bootstrap *subset;
	mach_port_t previous;

	syslog(LOG_DEBUG, "Subset create attempt: bootstrap %x, requestor: %x",
	      bootstrapport, requestorport);

	bootstrap = port_to_bootstrap(bootstrapport, true);
	if (!bootstrap)
		return BOOTSTRAP_NOT_PRIVILEGED;

	subset = bootstrap_new(bootstrap, requestorport);

	result = mach_port_request_notification(mach_task_self(), requestorport, MACH_NOTIFY_DEAD_NAME, 0,
			notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous); 
	if (result != KERN_SUCCESS) {
		syslog(LOG_ERR, "mach_port_request_notification(): %s", mach_error_string(result));
		mach_port_deallocate(mach_task_self(), requestorport);
		subset->requestor_port = MACH_PORT_NULL;
		bootstrap_deactivate(subset);
	} else if (previous != MACH_PORT_NULL) {
		syslog(LOG_DEBUG, "deallocating old notification port (%x) for requestor %x", previous, requestorport);
		result = mach_port_deallocate(mach_task_self(), previous);
		if (result != KERN_SUCCESS)
			panic("mach_port_deallocate(): %s", mach_error_string(result));
	}

	*subsetportp = subset->bootstrap_port;
	syslog(LOG_INFO, "Created bootstrap subset %x parent %x requestor %x", *subsetportp, bootstrapport, requestorport);
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_create_service(mach_port_t bootstrapport,
 *		      name_t servicename,
 *		      mach_port_t *serviceportp)
 *
 * Creates a service named "service_name" and returns send rights to that
 * port in "service_port."  The port may later be checked in as if this
 * port were configured in the bootstrap configuration file.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_NAME_IN_USE, if service already exists.
 */
__private_extern__ kern_return_t
x_bootstrap_create_service(mach_port_t bootstrapport, name_t servicename, mach_port_t *serviceportp)
{
	struct server *serverp;
	struct service *servicep;
	struct bootstrap *bootstrap;
	kern_return_t result;

	bootstrap = port_to_bootstrap(bootstrapport, true);
	if (!bootstrap)
		return BOOTSTRAP_NOT_PRIVILEGED;

	syslog(LOG_DEBUG, "Service creation attempt for service %s bootstrap %x", servicename, bootstrapport); 
	servicep = bootstrap_lookup_service(bootstrap, servicename);
	if (servicep) {
		syslog(LOG_DEBUG, "Service creation attempt for service %s failed, service already exists", servicename);
		return BOOTSTRAP_NAME_IN_USE;
	}

	serverp = port_to_server(bootstrapport);

	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, serviceportp);
	if (result != KERN_SUCCESS)
		panic("port_allocate(): %s", mach_error_string(result));
	result = mach_port_insert_right(mach_task_self(), *serviceportp, *serviceportp, MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS)
		panic("failed to insert send right(): %s", mach_error_string(result));

	if (serverp)
		serverp->activity++;

	servicep = service_new(bootstrap, servicename, *serviceportp, false, serverp);

	return BOOTSTRAP_SUCCESS;
}

mach_msg_return_t
inform_server_loop(mach_port_name_t about, mach_msg_option_t options)
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
	return mach_msg(&not.not_header, MACH_SEND_MSG|options, size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

void
notify_server_loop(mach_port_name_t about)
{
	mach_msg_return_t result;

	result = inform_server_loop(about, MACH_MSG_OPTION_NONE);
	if (result != MACH_MSG_SUCCESS)
		syslog(LOG_ERR, "notify_server_loop: mach_msg(): %s", mach_error_string(result));
}
