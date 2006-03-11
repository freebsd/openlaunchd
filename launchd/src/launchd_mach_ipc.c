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
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/exception.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <bsm/libbsm.h>
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


#include "bootstrap_public.h"
#include "bootstrap_private.h"
#include "bootstrap.h"
#include "bootstrapServer.h"
#include "notifyServer.h"
#include "launchd_internal.h"
#include "launchd_internalServer.h"
#include "launchd.h"
#include "launchd_core_logic.h"
#include "launch_priv.h"
#include "launchd_unix_ipc.h"

struct ldcred {
	uid_t	euid;
	uid_t	uid;
	gid_t	egid;
	gid_t	gid;
	pid_t	pid;
	au_asid_t asid;
};

static au_asid_t inherited_asid = 0;

static bool canReceive(mach_port_t);
static void init_ports(void);
static void *mport_demand_loop(void *arg);
static void audit_token_to_launchd_cred(audit_token_t au_tok, struct ldcred *ldc);

static mach_port_t inherited_bootstrap_port = MACH_PORT_NULL;
static mach_port_t demand_port_set = MACH_PORT_NULL;
static size_t port_to_obj_size = 0;
static void **port_to_obj = NULL;
static pthread_t demand_thread;

static bool trusted_client_check(struct jobcb *j, struct ldcred *ldc);

struct jobcb *
job_find_by_port(mach_port_t mp)
{
	return port_to_obj[MACH_PORT_INDEX(mp)];
}

kern_return_t
x_handle_mport(mach_port_t junk __attribute__((unused)), integer_t mport)
{
	struct kevent kev;

	EV_SET(&kev, mport, EVFILT_MACHPORT, 0, 0, 0, job_find_by_port(mport));
	(*((kq_callback *)kev.udata))(kev.udata, &kev);

	return 0;
}

void
mach_init_init(mach_port_t req_port, mach_port_t checkin_port,
		name_array_t l2l_names, mach_port_array_t l2l_ports, mach_msg_type_number_t l2l_cnt)
{
	mach_msg_type_number_t l2l_i;
	auditinfo_t inherited_audit;
	pthread_attr_t attr;

	getaudit(&inherited_audit);
	inherited_asid = inherited_audit.ai_asid;

	init_ports();

	launchd_assert((root_job = job_new_bootstrap(NULL, req_port ? req_port : mach_task_self(), checkin_port)) != NULL);

	launchd_assumes(launchd_get_bport(&inherited_bootstrap_port) == KERN_SUCCESS);

	if (getpid() != 1)
		launchd_assumes(inherited_bootstrap_port != MACH_PORT_NULL);

	/* We set this explicitly as we start each child */
	launchd_assumes(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);

	launchd_assert(pthread_create(&demand_thread, &attr, mport_demand_loop, NULL) == 0);

	pthread_attr_destroy(&attr);

	/* cut off the Libc cache, we don't want to deadlock against ourself */
	bootstrap_port = MACH_PORT_NULL;

	if (l2l_names == NULL)
		return;

	for (l2l_i = 0; l2l_i < l2l_cnt; l2l_i++) {
		struct machservice *ms;

		if ((ms = machservice_new(root_job, l2l_names[l2l_i], l2l_ports + l2l_i)))
			machservice_watch(ms);
	}
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
}

void *
mport_demand_loop(void *arg __attribute__((unused)))
{
	mach_msg_empty_rcv_t dummy;
	mach_port_name_array_t members;
	mach_msg_type_number_t membersCnt;
	mach_port_status_t status;
	mach_msg_type_number_t statusCnt;
	kern_return_t kr;
	unsigned int i;

	for (;;) {
		kr = mach_msg(&dummy.header, MACH_RCV_MSG|MACH_RCV_LARGE, 0, 0, demand_port_set, 0, MACH_PORT_NULL);
		if (kr == MACH_RCV_PORT_CHANGED) {
			break;
		} else if (!launchd_assumes(kr == MACH_RCV_TOO_LARGE)) {
			continue;
		}

		if (!launchd_assumes(mach_port_get_set_status(mach_task_self(), demand_port_set, &members, &membersCnt) == KERN_SUCCESS))
			continue;

		for (i = 0; i < membersCnt; i++) {
			statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
			if (mach_port_get_attributes(mach_task_self(), members[i], MACH_PORT_RECEIVE_STATUS,
						(mach_port_info_t)&status, &statusCnt) != KERN_SUCCESS)
				continue;

			if (status.mps_msgcount) {
				launchd_assumes(handle_mport(launchd_internal_port, members[i]) == 0);
				/* the callback may have tainted our ability to continue this for loop */
				break;
			}
		}

		launchd_assumes(vm_deallocate(mach_task_self(), (vm_address_t)members,
					(vm_size_t) membersCnt * sizeof(mach_port_name_t)) == KERN_SUCCESS);
	}

	return NULL;
}
								
boolean_t
launchd_mach_ipc_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply)
{
	if (bootstrap_server_routine(Request))
		return bootstrap_server(Request, Reply);

	return notify_server(Request, Reply);
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
	mach_port_t previous, where = (which == MACH_NOTIFY_NO_SENDERS) ? name : launchd_internal_port;

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
launchd_mport_request_callback(mach_port_t name, void *obj, bool readmsg)
{
	size_t needed_size;

	if (!obj)
		return errno = mach_port_move_member(mach_task_self(), name, MACH_PORT_NULL);

	needed_size = (MACH_PORT_INDEX(name) + 1) * sizeof(void *);

	if (needed_size > port_to_obj_size) {
		if (port_to_obj == NULL) {
			launchd_assumes((port_to_obj = calloc(1, needed_size * 2)) != NULL);
		} else {
			launchd_assumes((port_to_obj = reallocf(port_to_obj, needed_size * 2)) != NULL);
			memset((uint8_t *)port_to_obj + port_to_obj_size, 0, needed_size * 2 - port_to_obj_size);
		}
		port_to_obj_size = needed_size * 2;
	}

	port_to_obj[MACH_PORT_INDEX(name)] = obj;

	return errno = mach_port_move_member(mach_task_self(), name, readmsg ? ipc_port_set : demand_port_set);
}

kern_return_t
launchd_mport_make_send(mach_port_t name)
{
	return errno = mach_port_insert_right(mach_task_self(), name, name, MACH_MSG_TYPE_MAKE_SEND);
}

kern_return_t
launchd_mport_close_recv(mach_port_t name)
{
	if (launchd_assumes(port_to_obj != NULL)) {
		port_to_obj[MACH_PORT_INDEX(name)] = NULL;
		return errno = mach_port_mod_refs(mach_task_self(), name, MACH_PORT_RIGHT_RECEIVE, -1);
	} else {
		return errno = KERN_FAILURE;
	}
}

kern_return_t
launchd_mport_create_recv(mach_port_t *name)
{
	return errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, name);
}

kern_return_t
launchd_mport_deallocate(mach_port_t name)
{
	return errno = mach_port_deallocate(mach_task_self(), name);
}

void
audit_token_to_launchd_cred(audit_token_t au_tok, struct ldcred *ldc)
{
	audit_token_to_au32(au_tok, /* audit UID */ NULL,
			&ldc->euid, &ldc->egid,
			&ldc->uid, &ldc->gid, &ldc->pid,
			&ldc->asid, /* au_tid_t */ NULL);
}

kern_return_t
x_bootstrap_create_server(mach_port_t bp, cmd_t server_cmd, uid_t server_uid, boolean_t on_demand,
		audit_token_t au_tok, mach_port_t *server_portp)
{
	struct jobcb *js, *j = job_find_by_port(bp);
	struct ldcred ldc;

	audit_token_to_launchd_cred(au_tok, &ldc);

	job_log(j, LOG_DEBUG, "Server create attempt: %s", server_cmd);

#define LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	/* XXX - This code should go away once the per session launchd is integrated with the rest of the system */
	#ifdef LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	if (getpid() == 1) {
		if (ldc.euid != 0 && ldc.euid != server_uid) {
			job_log(j, LOG_WARNING, "Server create: \"%s\": Will run as UID %d, not UID %d as they told us to",
					server_cmd, ldc.euid, server_uid);
			server_uid = ldc.euid;
		}
	} else
#endif
	if (!trusted_client_check(j, &ldc)) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (server_uid != getuid()) {
		job_log(j, LOG_WARNING, "Server create: \"%s\": As UID %d, we will not be able to switch to UID %d",
				server_cmd, getuid(), server_uid);
		server_uid = getuid();
	}

	js = job_new_via_mach_init(j, server_cmd, server_uid, on_demand);

	if (js == NULL)
		return BOOTSTRAP_NO_MEMORY;

	*server_portp = job_get_bsport(js);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
x_bootstrap_getsocket(mach_port_t bp, name_t spr)
{
	strncpy(spr, sockpath, sizeof(name_t));

	if (getpid() == 1)
		return BOOTSTRAP_NOT_PRIVILEGED;
	
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
x_bootstrap_unprivileged(mach_port_t bp, mach_port_t *unprivportp)
{
	struct jobcb *j = job_find_by_port(bp);

	job_log(j, LOG_DEBUG, "Requested unprivileged bootstrap port");

	j = job_get_bs(j);

	*unprivportp = job_get_bsport(j);

	return BOOTSTRAP_SUCCESS;
}

  
kern_return_t
x_bootstrap_check_in(mach_port_t bp, name_t servicename, audit_token_t au_tok, mach_port_t *serviceportp)
{
	static pid_t last_warned_pid = 0;
	struct jobcb *j = job_find_by_port(bp);
	struct machservice *ms;
	struct ldcred ldc;

	audit_token_to_launchd_cred(au_tok, &ldc);

	trusted_client_check(j, &ldc);

	ms = job_lookup_service(j, servicename, true);

	if (ms == NULL) {
		job_log(j, LOG_DEBUG, "Check-in of Mach service failed. Unknown: %s", servicename);
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
	if (machservice_job(ms) != j) {
		if (last_warned_pid != ldc.pid) {
			job_log(j, LOG_NOTICE, "Check-in of Mach service failed. PID %d is not privileged: %s",
					ldc.pid, servicename);
			last_warned_pid = ldc.pid;
		}
		 return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (!canReceive(machservice_port(ms))) {
		launchd_assumes(machservice_active(ms));
		job_log(j, LOG_DEBUG, "Check-in of Mach service failed. Already active: %s", servicename);
		return BOOTSTRAP_SERVICE_ACTIVE;
	}

	machservice_watch(ms);

	job_log(j, LOG_INFO, "Check-in of service: %s", servicename);

	*serviceportp = machservice_port(ms);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
x_bootstrap_register(mach_port_t bp, audit_token_t au_tok, name_t servicename, mach_port_t serviceport)
{
	struct jobcb *j = job_find_by_port(bp);
	struct machservice *ms;
	struct ldcred ldc;

	audit_token_to_launchd_cred(au_tok, &ldc);

	trusted_client_check(j, &ldc);

	job_log(j, LOG_DEBUG, "Mach service registration attempt: %s", servicename);
	
	ms = job_lookup_service(j, servicename, false);

	if (ms) {
		if (machservice_job(ms) != j)
			return BOOTSTRAP_NOT_PRIVILEGED;
		if (machservice_active(ms)) {
			job_log(j, LOG_DEBUG, "Mach service registration failed. Already active: %s", servicename);
			launchd_assumes(!canReceive(machservice_port(ms)));
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		job_checkin(machservice_job(ms));
		machservice_delete(ms);
	}

	if (serviceport != MACH_PORT_NULL) {
		if ((ms = machservice_new(job_get_bs(j), servicename, &serviceport))) {
			machservice_watch(ms);
		} else {
			return BOOTSTRAP_NO_MEMORY;
		}
	}

	return BOOTSTRAP_SUCCESS;
}

kern_return_t
x_bootstrap_look_up(mach_port_t bp, audit_token_t au_tok, name_t servicename, mach_port_t *serviceportp, mach_msg_type_name_t *ptype)
{
	struct jobcb *j = job_find_by_port(bp);
	struct machservice *ms;
	struct ldcred ldc;

	audit_token_to_launchd_cred(au_tok, &ldc);

	trusted_client_check(j, &ldc);

	ms = job_lookup_service(j, servicename, true);

	if (ms && machservice_hidden(ms) && !job_active(machservice_job(ms))) {
		ms = NULL;
	}

	if (ms) {
		launchd_assumes(machservice_port(ms) != MACH_PORT_NULL);
		job_log(j, LOG_DEBUG, "Mach service lookup: %s", servicename);
		*serviceportp = machservice_port(ms);
		*ptype = MACH_MSG_TYPE_COPY_SEND;
		return BOOTSTRAP_SUCCESS;
	} else if (inherited_bootstrap_port != MACH_PORT_NULL) {
		job_log(j, LOG_DEBUG, "Mach service lookup forwarded: %s", servicename);
		*ptype = MACH_MSG_TYPE_MOVE_SEND;
		return bootstrap_look_up(inherited_bootstrap_port, servicename, serviceportp);
	} else {
		job_log(j, LOG_DEBUG, "Mach service lookup failed: %s", servicename);
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
}

kern_return_t
x_bootstrap_parent(mach_port_t bp, mach_port_t *parentport, mach_msg_type_name_t *pptype)
{
	struct jobcb *j = job_find_by_port(bp);

	job_log(j, LOG_DEBUG, "Requested parent bootstrap port");

	j = job_get_bs(j);

	*pptype = MACH_MSG_TYPE_MAKE_SEND;

	if (job_parent(j)) {
		*parentport = job_get_bsport(job_parent(j));
	} else if (MACH_PORT_NULL == inherited_bootstrap_port) {
		*parentport = job_get_bsport(j);
	} else {
		*pptype = MACH_MSG_TYPE_COPY_SEND;
		*parentport = inherited_bootstrap_port;
	}
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
	bootstrap_status_array_t service_actives;
	mach_port_array_t ports;
	unsigned int i;
};

static void
x_bootstrap_info_copyservices(struct machservice *ms, void *context)
{
	struct x_bootstrap_info_copyservices_cb *info_resp = context;

	strlcpy(info_resp->service_names[info_resp->i], machservice_name(ms), sizeof(info_resp->service_names[0]));

	launchd_assumes(info_resp->service_actives || info_resp->ports);

	if (info_resp->service_actives) {
		info_resp->service_actives[info_resp->i] = machservice_status(ms);
	} else {
		info_resp->ports[info_resp->i] = machservice_port(ms);
	}
	info_resp->i++;
}

kern_return_t
x_bootstrap_info(mach_port_t bp, name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		bootstrap_status_array_t *serviceactivesp, unsigned int *serviceactives_cnt)
{
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, 0 };
	struct jobcb *ji, *j = job_find_by_port(bp);
	kern_return_t result;
	unsigned int cnt = 0;

	for (ji = j; ji; ji = job_parent(ji))
		job_foreach_service(ji, x_bootstrap_info_countservices, &cnt, true);

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.service_actives, cnt * sizeof(info_resp.service_actives[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	for (ji = j; ji; ji = job_parent(ji))
		job_foreach_service(ji, x_bootstrap_info_copyservices, &info_resp, true);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*serviceactivesp = info_resp.service_actives;
	*servicenames_cnt = *serviceactives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names)
		vm_deallocate(mach_task_self(), (vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
x_bootstrap_transfer_subset(mach_port_t bp, mach_port_t *reqport, mach_port_t *rcvright,
	name_array_t *servicenamesp, unsigned int *servicenames_cnt,
	mach_port_array_t *ports, unsigned int *ports_cnt)
{
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, 0 };
	struct jobcb *j = job_find_by_port(bp);
	unsigned int cnt = 0;
	kern_return_t result;

	if (getpid() != 1) {
		job_log(j, LOG_ERR, "Only the system launchd will transfer Mach sub-bootstraps.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (!job_parent(j)) {
		job_log(j, LOG_ERR, "Root Mach bootstrap cannot be transferred.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	job_log(j, LOG_DEBUG, "Transferring sub-bootstrap to the per session launchd.");

	job_foreach_service(j, x_bootstrap_info_countservices, &cnt, false);

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	result = vm_allocate(mach_task_self(), (vm_address_t *)&info_resp.ports, cnt * sizeof(info_resp.ports[0]), true);
	if (!launchd_assumes(result == KERN_SUCCESS))
		goto out_bad;

	job_foreach_service(j, x_bootstrap_info_copyservices, &info_resp, false);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*ports = info_resp.ports;
	*servicenames_cnt = *ports_cnt = cnt;

	*reqport = job_get_reqport(j);
	*rcvright = job_get_bsport(j);

	launchd_assumes(launchd_mport_request_callback(*rcvright, NULL, true) == KERN_SUCCESS);

	launchd_assumes(launchd_mport_make_send(*rcvright) == KERN_SUCCESS);

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names)
		vm_deallocate(mach_task_self(), (vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
x_bootstrap_subset(mach_port_t bp, mach_port_t requestorport, mach_port_t *subsetportp)
{
	struct jobcb *js, *j = job_find_by_port(bp);
	int bsdepth = 0;

	while ((j = job_parent(j)) != NULL)
		bsdepth++;

	j = job_find_by_port(bp);

	/* Since we use recursion, we need an artificial depth for subsets */
	if (bsdepth > 100) {
		job_log(j, LOG_ERR, "Mach sub-bootstrap create request failed. Depth greater than: %d", bsdepth);
		return BOOTSTRAP_NO_MEMORY;
	}

	if ((js = job_new_bootstrap(j, requestorport, MACH_PORT_NULL)) == NULL) {
		if (requestorport == MACH_PORT_NULL)
			return BOOTSTRAP_NOT_PRIVILEGED;
		return BOOTSTRAP_NO_MEMORY;
	}

	*subsetportp = job_get_bsport(js);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
x_bootstrap_create_service(mach_port_t bp, name_t servicename, mach_port_t *serviceportp)
{
	struct jobcb *j = job_find_by_port(bp);
	struct machservice *ms;

	if (job_prog(j)[0] == '\0') {
		job_log(j, LOG_ERR, "Mach service creation requires a target server: %s", servicename);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	ms = job_lookup_service(j, servicename, false);
	if (ms) {
		job_log(j, LOG_DEBUG, "Mach service creation attempt for failed. Already exists: %s", servicename);
		return BOOTSTRAP_NAME_IN_USE;
	}

	job_checkin(j);

	ms = machservice_new(j, servicename, serviceportp);

	if (!launchd_assumes(ms != NULL))
		goto out_bad;

	return BOOTSTRAP_SUCCESS;

out_bad:
	launchd_assumes(launchd_mport_close_recv(*serviceportp) == KERN_SUCCESS);
	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
x_bootstrap_spawn(mach_port_t bp, audit_token_t au_tok,
		_internal_string_t charbuf, mach_msg_type_number_t charbuf_cnt,
		uint32_t argc, uint32_t envc, uint64_t flags, uint16_t mig_umask, pid_t *child_pid)
{
	struct jobcb *jr, *j = job_find_by_port(bp);
	struct ldcred ldc;
	size_t offset = 0;
	char *tmpp;
	const char **argv = NULL, **env = NULL;
	const char *label = NULL;
	const char *path = NULL;
	const char *workingdir = NULL;
	size_t argv_i = 0, env_i = 0;

	audit_token_to_launchd_cred(au_tok, &ldc);

#if 0
	if (ldc.asid != inherited_asid) {
		job_log(j, LOG_ERR, "Security: PID %d (ASID %d) was denied a request to spawn a process in this session (ASID %d)",
				ldc.pid, ldc.asid, inherited_asid);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
#endif

	argv = alloca((argc + 1) * sizeof(char *));
	memset(argv, 0, (argc + 1) * sizeof(char *));

	if (envc > 0) {
		env = alloca((envc + 1) * sizeof(char *));
		memset(env, 0, (envc + 1) * sizeof(char *));
	}

	while (offset < charbuf_cnt) {
		tmpp = charbuf + offset;
		offset += strlen(tmpp) + 1;
		if (!label) {
			label = tmpp;
		} else if (argc > 0) {
			argv[argv_i] = tmpp;
			argv_i++;
			argc--;
		} else if (envc > 0) {
			env[env_i] = tmpp;
			env_i++;
			envc--;
		} else if (flags & SPAWN_HAS_PATH) {
			path = tmpp;
			flags &= ~SPAWN_HAS_PATH;
		} else if (flags & SPAWN_HAS_WDIR) {
			workingdir = tmpp;
			flags &= ~SPAWN_HAS_WDIR;
		}
	}
	
	jr = job_new_spawn(label, path, workingdir, argv, env, flags & SPAWN_HAS_UMASK ? &mig_umask : NULL);

	if (jr == NULL) switch (errno) {
	case EEXIST:
		return BOOTSTRAP_NAME_IN_USE;
	default:
		return BOOTSTRAP_NO_MEMORY;
	}

	*child_pid = job_get_pid(jr);

	job_log(j, LOG_INFO, "Spawned PID %d", *child_pid);

	return BOOTSTRAP_SUCCESS;
}

kern_return_t
do_mach_notify_port_destroyed(mach_port_t notify, mach_port_t rights)
{
	/* This message is sent to us when a receive right is returned to us. */

	if (!job_ack_port_destruction(root_job, rights)) {
		launchd_assumes(launchd_mport_close_recv(rights) == KERN_SUCCESS);
	}

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
	struct jobcb *j = job_find_by_port(notify);

	/* This message is sent to us when the last customer of one of our objects
	 * goes away.
	 */

	if (!launchd_assumes(j != NULL))
		return KERN_FAILURE;

	job_ack_no_senders(j);

	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_send_once(mach_port_t notify)
{
	/*
	 * This message is sent to us every time we close a port that we have
	 * outstanding Mach notification requests on. We can safely ignore
	 * this message.
	 */
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_dead_name(mach_port_t notify, mach_port_name_t name)
{
	/* This message is sent to us when one of our send rights no longer has
	 * a receiver somewhere else on the system.
	 */

	if (name == inherited_bootstrap_port) {
		launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);
		inherited_bootstrap_port = MACH_PORT_NULL;
	}
		
	job_delete_anything_with_port(root_job, name);

	/* A dead-name notification about a port appears to increment the
	 * rights on said port. Let's deallocate it so that we don't leak
	 * dead-name ports.
	 */
	launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);

	return KERN_SUCCESS;
}

bool
trusted_client_check(struct jobcb *j, struct ldcred *ldc)
{
	static pid_t last_warned_pid = 0;

	/* In the long run, we wish to enforce the progeny rule, but for now,
	 * we'll let root and the user be forgiven. Once we get CoreProcesses
	 * to switch to using launchd rather than the WindowServer for indirect
	 * process invocation, we can then seriously look at cranking up the
	 * warning level here.
	 */

	if (inherited_asid == ldc->asid)
		return true;
	if (progeny_check(ldc->pid))
		return true;
	if (ldc->euid == geteuid())
		return true;
	if (ldc->euid == 0 && ldc->uid == 0)
		return true;
	if (last_warned_pid == ldc->pid)
		return false;

	job_log(j, LOG_NOTICE, "Security: PID %d (ASID %d) was leaked into this session (ASID %d). This will be denied in the future.", ldc->pid, ldc->asid, inherited_asid);

	last_warned_pid = ldc->pid;

	return false;
}
