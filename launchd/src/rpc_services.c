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
 * rpc_services.c -- implementation of bootstrap rpc services
 */

#import <mach/mach.h>
#import <string.h>

#import "bootstrap_internal.h"
#import "error_log.h"
#import "lists.h"
#import "bootstrap.h"

#ifndef ASSERT
#define ASSERT(p)
#endif

#ifndef NULL
#define	NULL	((void *)0)
#endif NULL
 
#define bsstatus(servicep) \
	(((servicep)->isActive) ? BOOTSTRAP_STATUS_ACTIVE : \
	 (((servicep)->server && (servicep)->server->servertype == DEMAND) ? \
		BOOTSTRAP_STATUS_ON_DEMAND : BOOTSTRAP_STATUS_INACTIVE))

/* extern port_all_t backup_port; */

/*
 * kern_return_t
 * bootstrap_create_server(mach_port_t bootstrap_port,
 *	 cmd_t server_cmd,
 *	 integer_t server_uid,
 *	 boolean_t on_demand,
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
kern_return_t
x_bootstrap_create_server(
	mach_port_t bootstrap_port,
	cmd_t server_cmd,
	int server_uid,
	boolean_t on_demand,
	security_token_t sectoken,
	mach_port_t *server_portp)
{
	server_t *serverp;
	bootstrap_info_t *bootstrap;

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	debug("Server create attempt: \"%s\" bootstrap %x",
	      server_cmd, bootstrap_port);

	/* No forwarding allowed for this call - security risk (we run as root) */
	if (!bootstrap || !active_bootstrap(bootstrap)) {
		debug("Server create: \"%s\": invalid bootstrap %x",
			server_cmd, bootstrap_port);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	/* only same uid (or root client) */
	if (sectoken.val[0] && sectoken.val[0] != server_uid) {
		notice("Server create: \"%s\": invalid security token (%d != %d)",
			server_cmd, sectoken.val[0], server_uid);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
	serverp = new_server(
					bootstrap,
					server_cmd,
					server_uid,
					(on_demand) ? DEMAND : RESTARTABLE);
	setup_server(serverp);

	info("New server %x in bootstrap %x: \"%s\"",
					serverp->port, bootstrap_port, server_cmd);
	*server_portp = serverp->port;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_unprivileged(mach_port_t bootstrap_port,
 *			  mach_port_t *unpriv_port)
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
kern_return_t
x_bootstrap_unprivileged(
	mach_port_t bootstrap_port,
	mach_port_t *unpriv_portp)
{
	bootstrap_info_t *bootstrap;

	debug("Get unprivileged attempt for bootstrap %x", bootstrap_port);

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	if (!bootstrap) {
		debug("Get unprivileged: invalid bootstrap %x", bootstrap_port);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	*unpriv_portp = bootstrap->bootstrap_port;

	debug ("Get unpriv bootstrap %x returned for bootstrap %x",
	       bootstrap->bootstrap_port, bootstrap_port);
	return BOOTSTRAP_SUCCESS;
}

  
/*
 * kern_return_t
 * bootstrap_check_in(mach_port_t bootstrap_port,
 *	 name_t service_name,
 *	 mach_port_t *service_portp)
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
kern_return_t
x_bootstrap_check_in(
	mach_port_t	bootstrap_port,
	name_t		service_name,
	mach_port_t	*service_portp)
{
	kern_return_t result;
	mach_port_t previous;
	service_t *servicep;
	server_t *serverp;
	bootstrap_info_t *bootstrap;

	serverp = lookup_server_by_port(bootstrap_port);
	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	debug("Service checkin attempt for service %s bootstrap %x",
	      service_name, bootstrap_port);

	servicep = lookup_service_by_name(bootstrap, service_name);
	if (servicep == NULL || servicep->port == MACH_PORT_NULL) {
		debug("bootstrap_check_in service %s unknown%s", service_name,
			forward_ok ? " forwarding" : "");
		return  forward_ok ?
			bootstrap_check_in(
					inherited_bootstrap_port,
					service_name,
					service_portp) :
			BOOTSTRAP_UNKNOWN_SERVICE;
	}
	if (servicep->server != NULL && servicep->server != serverp) {
		debug("bootstrap_check_in service %s not privileged",
			service_name);
		 return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (!canReceive(servicep->port)) {
		ASSERT(servicep->isActive);
		debug("bootstrap_check_in service %s already active",
			service_name);
		return BOOTSTRAP_SERVICE_ACTIVE;
	}
	debug("Checkin service %s for bootstrap %x", service_name,
	      bootstrap->bootstrap_port);
	ASSERT(servicep->isActive == FALSE);
	servicep->isActive = TRUE;

	if (servicep->server != NULL_SERVER) {
		/* registered server - service needs backup */
		serverp->activity++;
		serverp->active_services++;
		result = mach_port_request_notification(
					mach_task_self(),
					servicep->port,
					MACH_NOTIFY_PORT_DESTROYED,
					0,
					backup_port,
					MACH_MSG_TYPE_MAKE_SEND_ONCE,
					&previous);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_request_notification");
	} else {
		/* one time use/created service */
		servicep->servicetype = REGISTERED;
		result = mach_port_request_notification(
					mach_task_self(),
					servicep->port,
					MACH_NOTIFY_DEAD_NAME,
					0,
					notify_port,
					MACH_MSG_TYPE_MAKE_SEND_ONCE,
					&previous);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_request_notification");
		else if (previous != MACH_PORT_NULL) {
			debug("deallocating old notification port (%x) for checked in service %x",
				previous, servicep->port);
			result = mach_port_deallocate(
						mach_task_self(),
						previous);
			if (result != KERN_SUCCESS)
				kern_fatal(result, "mach_port_deallocate");
		}
	}

	info("Check-in service %x in bootstrap %x: %s",
	      servicep->port, servicep->bootstrap->bootstrap_port, servicep->name);

	*service_portp = servicep->port;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_register(mach_port_t bootstrap_port,
 *	name_t service_name,
 *	mach_port_t service_port)
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
kern_return_t
x_bootstrap_register(
	mach_port_t	bootstrap_port,
	name_t	service_name,
	mach_port_t	service_port)
{
	kern_return_t result;
	service_t *servicep;
	server_t *serverp;
	bootstrap_info_t *bootstrap;
	mach_port_t old_port;

	debug("Register attempt for service %s port %x",
	      service_name, service_port);

	/*
	 * Validate the bootstrap.
	 */
	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	if (!bootstrap || !active_bootstrap(bootstrap))
		return BOOTSTRAP_NOT_PRIVILEGED;
	  
	/*
	 * If this bootstrap port is for a server, or it's an unprivileged
	 * bootstrap can't register the port.
	 */
	serverp = lookup_server_by_port(bootstrap_port);
	servicep = lookup_service_by_name(bootstrap, service_name);
	if (servicep && servicep->server && servicep->server != serverp)
		return BOOTSTRAP_NOT_PRIVILEGED;

	if (servicep == NULL || servicep->bootstrap != bootstrap) {
		servicep = new_service(bootstrap,
				       service_name,
				       service_port,
				       ACTIVE,
				       REGISTERED,
				       NULL_SERVER);
		debug("Registered new service %s", service_name);
	} else {
		if (servicep->isActive) {
			debug("Register: service %s already active, port %x",
		 	      servicep->name, servicep->port);
			ASSERT(!canReceive(servicep->port));
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		old_port = servicep->port;
		if (servicep->servicetype == DECLARED) {
			servicep->servicetype = REGISTERED;

			if (servicep->server) {
				ASSERT(servicep->server == serverp);
				ASSERT(active_server(serverp));
				servicep->server = NULL_SERVER;
				serverp->activity++;
			}

			result = mach_port_mod_refs(
					mach_task_self(),
					old_port,
					MACH_PORT_RIGHT_RECEIVE, 
					-1);
			if (result != KERN_SUCCESS)
				kern_fatal(result, "mach_port_mod_refs");
		}
		result = mach_port_deallocate(
				mach_task_self(),
				old_port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_mod_refs");
		
		servicep->port = service_port;
		servicep->isActive = TRUE;
		debug("Re-registered inactive service %x bootstrap %x: %s",
			servicep->port, servicep->bootstrap->bootstrap_port, service_name);
	}

	/* detect the new service port going dead */
	result = mach_port_request_notification(
			mach_task_self(),
			service_port,
			MACH_NOTIFY_DEAD_NAME,
			0,
			notify_port,
			MACH_MSG_TYPE_MAKE_SEND_ONCE,
			&old_port);
	if (result != KERN_SUCCESS) {
		debug("Can't request notification on service %x bootstrap %x: %s",
		       service_port, servicep->bootstrap->bootstrap_port, "must be dead");
		delete_service(servicep);
		return BOOTSTRAP_SUCCESS;
	} else if (old_port != MACH_PORT_NULL) {
		debug("deallocating old notification port (%x) for service %x",
		      old_port, service_port);
		result = mach_port_deallocate(
				mach_task_self(),
				old_port);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_deallocate");
	}
	info("Registered service %x bootstrap %x: %s",
	     servicep->port, servicep->bootstrap->bootstrap_port, servicep->name);
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_look_up(mach_port_t bootstrap_port,
 *	name_t service_name,
 *	mach_port_t *service_portp)
 *
 * Returns send rights for the service port of the service named by
 * service_name in *service_portp.  Service is not guaranteed to be active.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_UNKNOWN_SERVICE, if service does not exist.
 */
kern_return_t
x_bootstrap_look_up(
	mach_port_t	bootstrap_port,
	name_t	service_name,
	mach_port_t	*service_portp)
{
	service_t *servicep;
	bootstrap_info_t *bootstrap;

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	servicep = lookup_service_by_name(bootstrap, service_name);
	if (servicep == NULL || servicep->port == MACH_PORT_NULL) {
		if (forward_ok) {
			debug("bootstrap_look_up service %s forwarding",
				service_name);
			return bootstrap_look_up(inherited_bootstrap_port,
						service_name,
						service_portp);
		} else {
			debug("bootstrap_look_up service %s unknown",
				service_name);
			return BOOTSTRAP_UNKNOWN_SERVICE;
		}
	}
	*service_portp = servicep->port;
	debug("Lookup returns port %x for service %s",
	      servicep->port,
	      servicep->name);
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_look_up_array(mach_port_t bootstrap_port,
 *	name_array_t	service_names,
 *	int		service_names_cnt,
 *	mach_port_array_t	*service_ports,
 *	int		*service_ports_cnt,
 *	boolean_t	*all_services_known)
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
kern_return_t
x_bootstrap_look_up_array(
	mach_port_t	bootstrap_port,
	name_array_t	service_names,
	unsigned int	service_names_cnt,
	mach_port_array_t	*service_portsp,
	unsigned int	*service_ports_cnt,
	boolean_t	*all_services_known)
{
	unsigned int i;
	static mach_port_t service_ports[BOOTSTRAP_MAX_LOOKUP_COUNT];
	
	if (service_names_cnt > BOOTSTRAP_MAX_LOOKUP_COUNT)
		return BOOTSTRAP_BAD_COUNT;
	*service_ports_cnt = service_names_cnt;
	*all_services_known = TRUE;
	for (i = 0; i < service_names_cnt; i++) {
		if (   x_bootstrap_look_up(bootstrap_port,
					  service_names[i],
					  &service_ports[i])
		    != BOOTSTRAP_SUCCESS)
		{
			*all_services_known = FALSE;
			service_ports[i] = MACH_PORT_NULL;
		}
	}
	debug("bootstrap_look_up_array returns %d ports", service_names_cnt);
	*service_portsp = service_ports;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_parent(mach_port_t bootstrap_port,
 *		    mach_port_t *parent_port);
 *
 * Given a bootstrap subset port, return the parent bootstrap port.
 * If the specified bootstrap port is already the root subset,
 * MACH_PORT_NULL will be returned.
 *
 * Errors:
 *	Returns BOOTSTRAP_NOT_PRIVILEGED if the caller is not running
 *	with an effective user id of root (as determined by the security
 *	token in the message trailer).
 */
kern_return_t
x_bootstrap_parent(
	mach_port_t bootstrap_port,
	security_token_t sectoken,
	mach_port_t *parent_port)
{
	bootstrap_info_t *bootstrap;

	debug("Parent attempt for bootstrap %x", bootstrap_port);

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	if (!bootstrap) { 
		debug("Parent attempt for bootstrap %x: invalid bootstrap",
		      bootstrap_port);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (sectoken.val[0]) {
		notice("Bootstrap parent for bootstrap %x: invalid security token (%d)",
		       bootstrap_port, sectoken.val[0]);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
	debug("Returning bootstrap parent %x for bootstrap %x",
	      bootstrap->parent->bootstrap_port, bootstrap_port);
	*parent_port = bootstrap->parent->bootstrap_port;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_status(mach_port_t bootstrap_port,
 *	name_t service_name,
 *	bootstrap_status_t *service_active);
 *
 * Returns: service_active indicates if service is available.
 *			
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_UNKNOWN_SERVICE, if service does not exist.
 */
kern_return_t
x_bootstrap_status(
	mach_port_t		bootstrap_port,
	name_t			service_name,
	bootstrap_status_t	*service_active)
{
	service_t *servicep;
	bootstrap_info_t *bootstrap;

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	servicep = lookup_service_by_name(bootstrap, service_name);
	if (servicep == NULL) {
		if (forward_ok) {
			debug("bootstrap_status forwarding status, server %s",
				service_name);
			return bootstrap_status(inherited_bootstrap_port,
						service_name,
						service_active);
		} else {
			debug("bootstrap_status service %s unknown",
				service_name);
			return BOOTSTRAP_UNKNOWN_SERVICE;
		}
	}
	*service_active = bsstatus(servicep);

	debug("bootstrap_status server %s %sactive", service_name,
		servicep->isActive ? "" : "in");
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_info(mach_port_t bootstrap_port,
 *	name_array_t *service_names,
 *	int *service_names_cnt,
 *	name_array_t *server_names,
 *	int *server_names_cnt,
 *	bootstrap_status_array_t *service_actives,
 *	int *service_active_cnt);
 *
 * Returns bootstrap status for all known services.
 *			
 * Errors:	Returns appropriate kernel errors on rpc failure.
 */
kern_return_t
x_bootstrap_info(
	mach_port_t			bootstrap_port,
	name_array_t			*service_namesp,
	unsigned int			*service_names_cnt,
	name_array_t			*server_namesp,
	unsigned int			*server_names_cnt,
	bootstrap_status_array_t	*service_activesp,
	unsigned int			*service_actives_cnt)
{
	kern_return_t result;
	unsigned int i, cnt;
	service_t *servicep;
	server_t *serverp;
	bootstrap_info_t *bootstrap;
	name_array_t service_names;
	name_array_t server_names;
	bootstrap_status_array_t service_actives;

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);

	for (   cnt = i = 0, servicep = services.next
	     ; i < nservices
	     ; servicep = servicep->next, i++)
	{
	    if (lookup_service_by_name(bootstrap, servicep->name) == servicep)
	    {
	    	cnt++;
	    }
	}
	result = vm_allocate(mach_task_self(),
			     (vm_address_t *)&service_names,
			     cnt * sizeof(service_names[0]),
			     ANYWHERE);
	if (result != KERN_SUCCESS)
		return BOOTSTRAP_NO_MEMORY;

	result = vm_allocate(mach_task_self(),
			     (vm_address_t *)&server_names,
			     cnt * sizeof(server_names[0]),
			     ANYWHERE);
	if (result != KERN_SUCCESS) {
		(void)vm_deallocate(mach_task_self(),
				    (vm_address_t)service_names,
				    cnt * sizeof(service_names[0]));
		return BOOTSTRAP_NO_MEMORY;
	}
	result = vm_allocate(mach_task_self(),
			     (vm_address_t *)&service_actives,
			     cnt * sizeof(service_actives[0]),
			     ANYWHERE);
	if (result != KERN_SUCCESS) {
		(void)vm_deallocate(mach_task_self(),
				    (vm_address_t)service_names,
				    cnt * sizeof(service_names[0]));
		(void)vm_deallocate(mach_task_self(),
				    (vm_address_t)server_names,
				    cnt * sizeof(server_names[0]));
		return BOOTSTRAP_NO_MEMORY;
	}

	for (  i = 0, servicep = services.next
	     ; i < cnt
	     ; servicep = servicep->next)
	{
	    if (   lookup_service_by_name(bootstrap, servicep->name)
		!= servicep)
		continue;
	    strncpy(service_names[i],
		    servicep->name,
		    sizeof(service_names[0]));
	    service_names[i][sizeof(service_names[0]) - 1] = '\0';
	    if (servicep->server) {
		    serverp = servicep->server;
		    strncpy(server_names[i],
			    serverp->cmd,
			    sizeof(server_names[0]));
		    server_names[i][sizeof(server_names[0]) - 1] = '\0';
		    debug("bootstrap info service %s server %s %sactive",
			servicep->name,
			serverp->cmd, servicep->isActive ? "" : "in"); 
	    } else {
		    server_names[i][0] = '\0';
		    debug("bootstrap info service %s %sactive",
			servicep->name, servicep->isActive ? "" : "in"); 
	    }
	    service_actives[i] = bsstatus(servicep);
	    i++;
	}
	*service_namesp = service_names;
	*server_namesp = server_names;
	*service_activesp = service_actives;
	*service_names_cnt = *server_names_cnt =
		*service_actives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_subset(mach_port_t bootstrap_port,
 *		    mach_port_t requestor_port,
 *		    mach_port_t *subset_port);
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
 * When it is detected that the requestor_port is destroied the subset
 * port and all services advertized by it are destroied as well.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 */
kern_return_t
x_bootstrap_subset(
	mach_port_t	bootstrap_port,
	mach_port_t	requestor_port,
	mach_port_t	*subset_port)
{
	kern_return_t result;
	bootstrap_info_t *bootstrap;
	bootstrap_info_t *subset;
	mach_port_t new_bootstrap_port;
	mach_port_t previous;

	debug("Subset create attempt: bootstrap %x, requestor: %x",
	      bootstrap_port, requestor_port);

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	if (!bootstrap || !active_bootstrap(bootstrap))
		return BOOTSTRAP_NOT_PRIVILEGED;

	result = mach_port_allocate(
				mach_task_self(), 
				MACH_PORT_RIGHT_RECEIVE,
				&new_bootstrap_port);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "mach_port_allocate");

	result = mach_port_insert_right(
				mach_task_self(),
				new_bootstrap_port,
				new_bootstrap_port,
				MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "failed to insert send right");

	result = mach_port_insert_member(
				mach_task_self(),
				new_bootstrap_port,
				bootstrap_port_set);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "port_set_add");

	subset = new_bootstrap(bootstrap, new_bootstrap_port, requestor_port);

	result = mach_port_request_notification(
				mach_task_self(),
				requestor_port,
				MACH_NOTIFY_DEAD_NAME,
				0,
				notify_port,
				MACH_MSG_TYPE_MAKE_SEND_ONCE,
				&previous); 
	if (result != KERN_SUCCESS) {
		kern_error(result, "mach_port_request_notification");
		mach_port_deallocate(mach_task_self(), requestor_port);
		subset->requestor_port = MACH_PORT_NULL;
		deactivate_bootstrap(subset);
	} else if (previous != MACH_PORT_NULL) {
		debug("deallocating old notification port (%x) for requestor %x",
			  previous, requestor_port);
		result = mach_port_deallocate(
				mach_task_self(),
				previous);
		if (result != KERN_SUCCESS)
			kern_fatal(result, "mach_port_deallocate");
	}

	info("Created bootstrap subset %x parent %x requestor %x", 
		new_bootstrap_port, bootstrap_port, requestor_port);
	*subset_port = new_bootstrap_port;
	return BOOTSTRAP_SUCCESS;
}

/*
 * kern_return_t
 * bootstrap_create_service(mach_port_t bootstrap_port,
 *		      name_t service_name,
 *		      mach_port_t *service_port)
 *
 * Creates a service named "service_name" and returns send rights to that
 * port in "service_port."  The port may later be checked in as if this
 * port were configured in the bootstrap configuration file.
 *
 * Errors:	Returns appropriate kernel errors on rpc failure.
 *		Returns BOOTSTRAP_NAME_IN_USE, if service already exists.
 */
kern_return_t
x_bootstrap_create_service(
	mach_port_t bootstrap_port,
	name_t	service_name,
	mach_port_t *service_port)
{
	server_t *serverp;
	service_t *servicep;
	bootstrap_info_t *bootstrap;
	kern_return_t result;

	bootstrap = lookup_bootstrap_by_port(bootstrap_port);
	if (!bootstrap || !active_bootstrap(bootstrap))
		return BOOTSTRAP_NOT_PRIVILEGED;

	debug("Service creation attempt for service %s bootstrap %x",
	      service_name, bootstrap_port);

	servicep = lookup_service_by_name(bootstrap, service_name);
	if (servicep) {
		debug("Service creation attempt for service %s failed, "
			"service already exists", service_name);
		return BOOTSTRAP_NAME_IN_USE;
	}

	serverp = lookup_server_by_port(bootstrap_port);

	result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,  service_port);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "port_allocate");
	result = mach_port_insert_right(mach_task_self(), *service_port, *service_port, MACH_MSG_TYPE_MAKE_SEND);
	if (result != KERN_SUCCESS)
		kern_fatal(result, "failed to insert send right");

	if (serverp)
		serverp->activity++;

	servicep = new_service(bootstrap,
				service_name,
				*service_port,
				!ACTIVE,
				DECLARED,
				serverp);

	info("Created new service %x in bootstrap %x: %s", 
	    servicep->port, bootstrap->bootstrap_port, service_name);

	return BOOTSTRAP_SUCCESS;
}
