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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>

/* <rdar://problem/2685209> sys/queue.h is not up to date */
#ifndef SLIST_FOREACH_SAFE
#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SLIST_FIRST((head));				\
		(var) && ((tvar) = SLIST_NEXT((var), field), 1);	\
		(var) = (tvar))
#endif


#include "bootstrap.h"
#include "bootstrapServer.h"
#include "notifyServer.h"
#include "launchd.h"
#include "launchd_core_logic.h"

static bool canReceive(mach_port_t);
static void init_ports(void);
static void *demand_loop(void *arg);
static void mport_callback(void *obj, struct kevent *kev);

static mach_port_t inherited_bootstrap_port = MACH_PORT_NULL;
static mach_port_t demand_port_set = MACH_PORT_NULL;
static mach_port_t notify_port = MACH_PORT_NULL;
static char *register_name = NULL;
static size_t port_to_obj_size = 0;
static void **port_to_obj = NULL;
static int main_to_demand_loop_fd = -1;
static int demand_loop_to_main_fd = -1;
static pthread_t demand_thread;
static kq_callback kqmport_callback = mport_callback;
static kq_callback kqbstrap_callback = bootstrap_callback;

void mport_callback(void *obj, struct kevent *kev)
{
	struct kevent newkev;
	mach_port_name_array_t members;
	mach_msg_type_number_t membersCnt;
	mach_port_status_t status;
	mach_msg_type_number_t statusCnt;
	unsigned int i;
	char junk = '\0';

	launchd_assumes(read(main_to_demand_loop_fd, &junk, sizeof(junk)) != -1);

	if (!launchd_assumes(mach_port_get_set_status(mach_task_self(), demand_port_set, &members, &membersCnt) == KERN_SUCCESS))
		goto out;

	for (i = 0; i < membersCnt; i++) {
		statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
		if (mach_port_get_attributes(mach_task_self(), members[i], MACH_PORT_RECEIVE_STATUS,
					(mach_port_info_t)&status, &statusCnt) != KERN_SUCCESS)
			break;

		if (status.mps_msgcount) {
			EV_SET(&newkev, members[i], EVFILT_MACHPORT, 0, 0, 0, port_to_obj[MACH_PORT_INDEX(members[i])]);
			(*((kq_callback *)newkev.udata))(newkev.udata, &newkev);

			/* the callback may have tained our ability to continue this for loop */
			break;
		}
	}

	launchd_assumes(vm_deallocate(mach_task_self(), (vm_address_t)members,
				(vm_size_t) membersCnt * sizeof(mach_port_name_t)) == KERN_SUCCESS);

out:
	launchd_assumes(write(main_to_demand_loop_fd, &junk, sizeof(junk)) != -1);
}

void mach_init_init(void)
{
#ifdef PROTECT_WINDOWSERVER_BS_PORT
	struct stat sb;
#endif
	pthread_attr_t attr;
	int pipepair[2];

	init_ports();

	launchd_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pipepair) != -1);

	main_to_demand_loop_fd = _fd(pipepair[0]);
	demand_loop_to_main_fd = _fd(pipepair[1]);

	launchd_assert(kevent_mod(main_to_demand_loop_fd, EVFILT_READ, EV_ADD, 0, 0, &kqmport_callback) != -1);

	launchd_assert((root_bootstrap = bootstrap_new(NULL, MACH_PORT_NULL)) != NULL);

#ifdef PROTECT_WINDOWSERVER_BS_PORT
	if (stat("/System/Installation", &sb) == 0 && stat("/etc/rc.cdrom", &sb) == 0) {
#endif
		ws_bootstrap = root_bootstrap;
#ifdef PROTECT_WINDOWSERVER_BS_PORT
	} else {
		launchd_assert((ws_bootstrap = bootstrap_new(root_bootstrap, MACH_PORT_NULL)) != NULL);
	}
#endif
	
	launchd_assumes(launchd_get_bport(&inherited_bootstrap_port) == KERN_SUCCESS);

	if (getpid() != 1)
		launchd_assumes(inherited_bootstrap_port != MACH_PORT_NULL);

	/* We set this explicitly as we start each child */
	launchd_assumes(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);

	/* register "self" port with anscestor */		
	if (inherited_bootstrap_port != MACH_PORT_NULL) {
		asprintf(&register_name, "com.apple.launchd.%d", getpid());

		launchd_assumes(launchd_mport_make_send(bootstrap_rport(root_bootstrap)) == KERN_SUCCESS);
		launchd_assumes(bootstrap_register(inherited_bootstrap_port, register_name,
					bootstrap_rport(root_bootstrap)) == KERN_SUCCESS);
		launchd_assumes(launchd_mport_deallocate(bootstrap_rport(root_bootstrap)) == KERN_SUCCESS);
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	launchd_assert(pthread_create(&demand_thread, &attr, demand_loop, NULL) == 0);

	pthread_attr_destroy(&attr);

	/* cut off the Libc cache, we don't want to deadlock against ourself */
	bootstrap_port = MACH_PORT_NULL;
}

void mach_init_reap(void)
{
	void *status;

	launchd_assumes(mach_port_destroy(mach_task_self(), demand_port_set) == KERN_SUCCESS);

	launchd_assumes(pthread_join(demand_thread, &status) == 0);
}

void
init_ports(void)
{
	launchd_assert((errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET,
					&demand_port_set)) == KERN_SUCCESS);
	
	launchd_assert(launchd_mport_create_recv(&notify_port, &kqbstrap_callback) == KERN_SUCCESS);

	launchd_assert(launchd_mport_watch(notify_port) == KERN_SUCCESS);
}

void *
demand_loop(void *arg __attribute__((unused)))
{
	mach_msg_empty_rcv_t dummy;
	kern_return_t dresult;
	char junk = '\0';

	for (;;) {
		dresult = mach_msg(&dummy.header, MACH_RCV_MSG|MACH_RCV_LARGE, 0, 0, demand_port_set, 0, MACH_PORT_NULL);
		if (dresult == MACH_RCV_PORT_CHANGED) {
			break;
		} else if (!launchd_assumes(dresult == MACH_RCV_TOO_LARGE)) {
			continue;
		}
		/* This is our brain dead way of telling the main thread there
		 * is work to do and waiting for the main thread to tell us
		 * when it is safe to check the Mach port-set again.
		 */
		launchd_assumes(write(demand_loop_to_main_fd, &junk, sizeof(junk)) != -1);
		launchd_assumes(read(demand_loop_to_main_fd, &junk, sizeof(junk)) != -1);
	}
	return NULL;
}
								
boolean_t
launchd_mach_ipc_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply)
{
	return bootstrap_server(Request, Reply) ? true : notify_server(Request, Reply);
}

bool
canReceive(mach_port_t port)
{
	mach_port_type_t p_type;
	
	if (!launchd_assumes(mach_port_type(mach_task_self(), port, &p_type) == KERN_SUCCESS))
		return false;

	return ((p_type & MACH_PORT_TYPE_RECEIVE) != 0);
}

kern_return_t
launchd_set_bport(mach_port_t name)
{
	return errno = task_set_bootstrap_port(mach_task_self(), name);
}

kern_return_t
launchd_get_bport(mach_port_t *name)
{
	return errno = task_get_bootstrap_port(mach_task_self(), name);
}

kern_return_t
launchd_mport_notify_req(mach_port_t name, mach_msg_id_t which)
{
	mach_port_mscount_t msgc = (which == MACH_NOTIFY_NO_SENDERS) ? 1 : 0;
	mach_port_t previous, where = (which == MACH_NOTIFY_NO_SENDERS) ? name : notify_port;

	if (which == MACH_NOTIFY_NO_SENDERS) {
		/* Always make sure the send count is zero, in case a receive right is reused */
		errno = mach_port_set_mscount(mach_task_self(), name, 0);
		if (errno != KERN_SUCCESS)
			return errno;
	}

	errno = mach_port_request_notification(mach_task_self(), name, which, msgc, where,
			MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);

	if (errno == 0 && previous != MACH_PORT_NULL)
		launchd_assumes(launchd_mport_deallocate(previous) == KERN_SUCCESS);

	return errno;
}

kern_return_t
launchd_mport_watch(mach_port_t name)
{
	return errno = mach_port_move_member(mach_task_self(), name, demand_port_set);
}

kern_return_t
launchd_mport_ignore(mach_port_t name)
{
	return errno = mach_port_move_member(mach_task_self(), name, MACH_PORT_NULL);
}

kern_return_t
launchd_mport_make_send(mach_port_t name)
{
	return errno = mach_port_insert_right(mach_task_self(), name, name, MACH_MSG_TYPE_MAKE_SEND);
}

kern_return_t
launchd_mport_close_recv(mach_port_t name)
{
	if (launchd_assumes(port_to_obj != NULL))
		port_to_obj[MACH_PORT_INDEX(name)] = NULL;

	return errno = mach_port_mod_refs(mach_task_self(), name, MACH_PORT_RIGHT_RECEIVE, -1);
}

kern_return_t
launchd_mport_create_recv(mach_port_t *name, void *obj)
{
	size_t needed_size;
	kern_return_t result;

	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, name);

	if (result != KERN_SUCCESS)
		return errno = result;

	needed_size = (MACH_PORT_INDEX(*name) + 1) * sizeof(void *);

	if (needed_size > port_to_obj_size) {
		if (port_to_obj == NULL) {
			launchd_assumes((port_to_obj = calloc(1, needed_size * 2)) != NULL);
		} else {
			launchd_assumes((port_to_obj = reallocf(port_to_obj, needed_size * 2)) != NULL);
			memset((uint8_t *)port_to_obj + port_to_obj_size, 0, needed_size * 2 - port_to_obj_size);
		}
		port_to_obj_size = needed_size * 2;
	}

	launchd_assumes(port_to_obj[MACH_PORT_INDEX(*name)] == NULL);

	port_to_obj[MACH_PORT_INDEX(*name)] = obj;

	return errno = result;
}

kern_return_t
launchd_mport_deallocate(mach_port_t name)
{
	return errno = mach_port_deallocate(mach_task_self(), name);
}


#define bsstatus(servicep) \
	((machservice_active(servicep)) ? BOOTSTRAP_STATUS_ACTIVE : \
	 ((machservice_job(servicep) && job_ondemand(machservice_job(servicep))) ? \
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct jobcb *j;

	uid_t client_euid = sectoken.val[0];

	syslog(LOG_DEBUG, "Server create attempt: \"%s\" bootstrap %x", server_cmd, bootstrapport);

#define LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	/* XXX - This code should go away once the per session launchd is integrated with the rest of the system */
#ifdef LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	if (getpid() == 1) {
		if (client_euid != 0 && client_euid != server_uid) {
			syslog(LOG_WARNING, "Server create: \"%s\": Will run as UID %d, not UID %d as they told us to",
					server_cmd, client_euid, server_uid);
			server_uid = client_euid;
		}
		if (client_euid == 0 && strstr(server_cmd, "WindowServer"))
			bootstrap = ws_bootstrap;
	} else
#endif
	if (client_euid != 0 && client_euid != getuid()) {
		syslog(LOG_ALERT, "Security: UID %d somehow acquired the bootstrap port of UID %d and tried to create a server. Denied.",
				client_euid, getuid());
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (server_uid != getuid()) {
		syslog(LOG_WARNING, "Server create: \"%s\": As UID %d, we will not be able to switch to UID %d",
				server_cmd, getuid(), server_uid);
		server_uid = getuid();
	}

	j = job_new_via_mach_init(bootstrap, server_cmd, server_uid, on_demand);

	*server_portp = job_get_priv_port(j);
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;

	*unprivportp = bootstrap_rport(bootstrap);

	syslog(LOG_DEBUG, "Get unpriv bootstrap %x returned for bootstrap %x", bootstrap_rport(bootstrap), bootstrapport);
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct jobcb *j = current_rpc_server;
	kern_return_t result;
	struct machservice *servicep;

	syslog(LOG_DEBUG, "Service checkin attempt for service %s bootstrap %x", servicename, bootstrapport);

	servicep = bootstrap_lookup_service(bootstrap, servicename, true);
	if (servicep == NULL || !launchd_assumes(machservice_port(servicep) != MACH_PORT_NULL)) {
		syslog(LOG_DEBUG, "bootstrap_check_in service %s unknown%s", servicename, inherited_bootstrap_port != MACH_PORT_NULL ? " forwarding" : "");
		result = BOOTSTRAP_UNKNOWN_SERVICE;
		if (inherited_bootstrap_port != MACH_PORT_NULL)
			result = bootstrap_check_in(inherited_bootstrap_port, servicename, serviceportp);
		return result;
	}
	if (machservice_job(servicep) && machservice_job(servicep) != j) {
		syslog(LOG_DEBUG, "bootstrap_check_in service %s not privileged", servicename);
		 return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (!canReceive(machservice_port(servicep))) {
		launchd_assumes(machservice_active(servicep));
		syslog(LOG_DEBUG, "bootstrap_check_in service %s already active", servicename);
		return BOOTSTRAP_SERVICE_ACTIVE;
	}

	machservice_watch(servicep);

	syslog(LOG_INFO, "Checkin service %x in bootstrap %x: %s", machservice_port(servicep), bootstrap_rport(machservice_bootstrap(servicep)), machservice_name(servicep));

	*serviceportp = machservice_port(servicep);
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct jobcb *j = current_rpc_server;
	struct machservice *servicep;

	syslog(LOG_DEBUG, "Register attempt for service %s port %x", servicename, serviceport);

	servicep = bootstrap_lookup_service(bootstrap, servicename, false);

	if (servicep) {
		if (machservice_job(servicep) && machservice_job(servicep) != j)
			return BOOTSTRAP_NOT_PRIVILEGED;
		if (machservice_active(servicep)) {
			syslog(LOG_DEBUG, "Register: service %s already active, port %x", machservice_name(servicep), machservice_port(servicep));
			launchd_assumes(!canReceive(machservice_port(servicep)));
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		if (machservice_job(servicep))
			job_checkin(j);
		machservice_delete(servicep);
	}

	if (serviceport != MACH_PORT_NULL) {
		servicep = machservice_new(bootstrap, servicename, &serviceport, NULL);
		machservice_watch(servicep);
		syslog(LOG_INFO, "Registered service %x bootstrap %x: %s", machservice_port(servicep),
				bootstrap_rport(machservice_bootstrap(servicep)), machservice_name(servicep));
	}

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
x_bootstrap_look_up(mach_port_t bootstrapport, name_t servicename, mach_port_t *serviceportp, mach_msg_type_name_t *ptype)
{
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct machservice *servicep;

	servicep = bootstrap_lookup_service(bootstrap, servicename, true);
	if (servicep) {
		launchd_assumes(machservice_port(servicep) != MACH_PORT_NULL);
		syslog(LOG_DEBUG, "bootstrap_look_up service %s returned %x", servicename, machservice_port(servicep));
		*serviceportp = machservice_port(servicep);
		*ptype = MACH_MSG_TYPE_COPY_SEND;
		return BOOTSTRAP_SUCCESS;
	} else if (inherited_bootstrap_port != MACH_PORT_NULL) {
		syslog(LOG_DEBUG, "bootstrap_look_up service %s forwarding", servicename);
		*ptype = MACH_MSG_TYPE_MOVE_SEND;
		return bootstrap_look_up(inherited_bootstrap_port, servicename, serviceportp);
	} else {
		syslog(LOG_DEBUG, "bootstrap_look_up service %s unknown", servicename);
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
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
	mach_msg_type_name_t ptype;
	
	if (servicenames_cnt > BOOTSTRAP_MAX_LOOKUP_COUNT)
		return BOOTSTRAP_BAD_COUNT;
	*serviceports_cnt = servicenames_cnt;
	*allservices_known = true;
	for (i = 0; i < servicenames_cnt; i++) {
		if (x_bootstrap_look_up(bootstrapport, servicenames[i], &service_ports[i], &ptype) != BOOTSTRAP_SUCCESS) {
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
x_bootstrap_parent(mach_port_t bootstrapport, security_token_t sectoken, mach_port_t *parentport, mach_msg_type_name_t *pptype)
{
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	uid_t u = sectoken.val[0];

	syslog(LOG_DEBUG, "Parent attempt for bootstrap %x", bootstrapport);

	if (u) {
		syslog(LOG_NOTICE, "UID %d was denied an answer to bootstrap_parent().", u);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	*pptype = MACH_MSG_TYPE_MAKE_SEND;

	if (bootstrap_rparent(bootstrap)) {
		*parentport = bootstrap_rport(bootstrap_rparent(bootstrap));
	} else if (MACH_PORT_NULL == inherited_bootstrap_port) {
		*parentport = bootstrap_rport(bootstrap);
	} else {
		*pptype = MACH_MSG_TYPE_COPY_SEND;
		*parentport = inherited_bootstrap_port;
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct machservice *servicep;

	servicep = bootstrap_lookup_service(bootstrap, servicename, true);
	if (servicep == NULL) {
		if (inherited_bootstrap_port != MACH_PORT_NULL) {
			syslog(LOG_DEBUG, "bootstrap_status forwarding status, server %s", servicename);
			return bootstrap_status(inherited_bootstrap_port, servicename, serviceactivep);
		} else {
			syslog(LOG_DEBUG, "bootstrap_status service %s unknown", servicename);
			return BOOTSTRAP_UNKNOWN_SERVICE;
		}
	}
	*serviceactivep = bsstatus(servicep);

	syslog(LOG_DEBUG, "bootstrap_status server %s %sactive", servicename, machservice_active(servicep) ? "" : "in");
	return BOOTSTRAP_SUCCESS;
}

static void
x_bootstrap_info_countservices(struct machservice *ms, void *context)
{
	unsigned int *cnt = context;

	(*cnt)++;
}

struct x_bootstrap_info_copyservices_cb {
	name_array_t service_names;
	name_array_t server_names;
	bootstrap_status_array_t service_actives;
	unsigned int i;
};

static void
x_bootstrap_info_copyservices(struct machservice *ms, void *context)
{
	struct x_bootstrap_info_copyservices_cb *info_resp = context;
	const char *svr_name = "";

	if (machservice_job(ms))
		svr_name = job_prog(machservice_job(ms));

	strlcpy(info_resp->service_names[info_resp->i], machservice_name(ms), sizeof(info_resp->service_names[0]));
	strlcpy(info_resp->server_names[info_resp->i], svr_name, sizeof(info_resp->server_names[0]));
	info_resp->service_actives[info_resp->i] = bsstatus(ms);
	info_resp->i++;
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
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, 0 };
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct bootstrap *bstrap_iter;
	kern_return_t result;
	unsigned int cnt = 0;

	for (bstrap_iter = bootstrap; bstrap_iter; bstrap_iter = bootstrap_rparent(bstrap_iter))
		bootstrap_foreach_service(bstrap_iter, x_bootstrap_info_countservices, &cnt);

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.server_names, cnt * sizeof(info_resp.server_names[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.service_actives, cnt * sizeof(info_resp.service_actives[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	for (bstrap_iter = bootstrap; bstrap_iter; bstrap_iter = bootstrap_rparent(bstrap_iter))
		bootstrap_foreach_service(bstrap_iter, x_bootstrap_info_copyservices, &info_resp);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*servernamesp = info_resp.server_names;
	*serviceactivesp = info_resp.service_actives;
	*servicenames_cnt = *servernames_cnt = *serviceactives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names)
		vm_deallocate(mach_task_self(), (vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	if (info_resp.server_names)
		vm_deallocate(mach_task_self(), (vm_address_t)info_resp.server_names, cnt * sizeof(info_resp.server_names[0]));

	return BOOTSTRAP_NO_MEMORY;
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct bootstrap *subset;
	int bsdepth = 0;

	while ((bootstrap = bootstrap_rparent(bootstrap)) != NULL)
		bsdepth++;

	bootstrap = current_rpc_bootstrap;

	/* Since we use recursion, we need an artificial depth for subsets */
	if (bsdepth > 100)
		return BOOTSTRAP_NO_MEMORY;

	if (!launchd_assumes(requestorport != MACH_PORT_NULL))
		return BOOTSTRAP_NOT_PRIVILEGED;

	syslog(LOG_DEBUG, "Subset create attempt: bootstrap %x, requestor: %x", bootstrapport, requestorport);

	subset = bootstrap_new(bootstrap, requestorport);

	if (subset == NULL)
		return BOOTSTRAP_NO_MEMORY;

	*subsetportp = bootstrap_rport(subset);
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
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct jobcb *j = current_rpc_server;
	struct machservice *servicep;

	syslog(LOG_DEBUG, "Service creation attempt for service %s bootstrap %x", servicename, bootstrapport); 
	servicep = bootstrap_lookup_service(bootstrap, servicename, false);
	if (servicep) {
		syslog(LOG_DEBUG, "Service creation attempt for service %s failed, service already exists", servicename);
		return BOOTSTRAP_NAME_IN_USE;
	}

	if (j)
		job_checkin(j);

	servicep = machservice_new(bootstrap, servicename, serviceportp, j ? j : ANY_JOB);

	if (!launchd_assumes(servicep != NULL))
		goto out_bad;

	return BOOTSTRAP_SUCCESS;

out_bad:
	launchd_assumes(launchd_mport_close_recv(*serviceportp) == KERN_SUCCESS);
	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
do_mach_notify_port_destroyed(mach_port_t notify, mach_port_t rights)
{
	struct jobcb *j;

	/* This message is sent to us when a receive right is returned to us. */

	if (!launchd_assumes((j = port_to_obj[MACH_PORT_INDEX(rights)]) != NULL))
		return KERN_FAILURE;

	job_ack_port_destruction(j, rights);
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_port_deleted(mach_port_t notify, mach_port_name_t name)
{
	/* If we deallocate/destroy/mod_ref away a port with a pending notification,
	 * the original notification message is replaced with this message.
	 *
	 * To quote a Mach kernel expert, "the kernel has a send-once right that has
	 * to be used somehow."
	 */
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_no_senders(mach_port_t notify, mach_port_mscount_t mscount)
{
	struct bootstrap *bootstrap = current_rpc_bootstrap;
	struct jobcb *j = current_rpc_server;

	/* This message is sent to us when the last customer of one of our objects
	 * goes away.
	 */

	if (!launchd_assumes(bootstrap != NULL))
		return KERN_FAILURE;

	if (j) {
		job_ack_no_senders(j);
	} else {
		syslog(LOG_DEBUG, "Deallocating bootstrap %d: no more clients", MACH_PORT_INDEX(notify));
		bootstrap_delete(bootstrap);
	}

	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_send_once(mach_port_t notify)
{
	launchd_assumes(false);
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_dead_name(mach_port_t notify, mach_port_name_t name)
{
	/* This message is sent to us when one of our send rights no longer has
	 * a receiver somewhere else on the system.
	 */

	syslog(LOG_DEBUG, "Dead name notification: %d", MACH_PORT_INDEX(name));

	if (name == inherited_bootstrap_port) {
		launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);
		inherited_bootstrap_port = MACH_PORT_NULL;
	}
		
	bootstrap_delete_anything_with_port(root_bootstrap, name);

	/* A dead-name notification about a port appears to increment the
	 * rights on said port. Let's deallocate it so that we don't leak
	 * dead-name ports.
	 */
	launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);

	return KERN_SUCCESS;
}
