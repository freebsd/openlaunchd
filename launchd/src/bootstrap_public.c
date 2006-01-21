/*
 * Copyright (c) 1999-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <mach/mach.h>
#include <mach/vm_map.h>

#include "bootstrap_public.h"
#include "bootstrap_private.h"

#define mig_external static
#include "bootstrap.h"
#include "bootstrapUser.c"

kern_return_t
_launchd_to_launchd(mach_port_t bp, mach_port_t *reqport, mach_port_t *rcvright,
		name_array_t *service_names, mach_msg_type_number_t *service_namesCnt,
		mach_port_array_t *ports, mach_msg_type_number_t *portCnt)
{
	return raw_bootstrap_transfer_subset(bp, reqport, rcvright, service_names, service_namesCnt, ports, portCnt);
}

kern_return_t
bootstrap_create_server(mach_port_t bp, cmd_t server_cmd, uid_t server_uid, boolean_t on_demand, mach_port_t *server_port)
{
	return raw_bootstrap_create_server(bp, server_cmd, server_uid, on_demand, server_port);
}

kern_return_t
bootstrap_subset(mach_port_t bp, mach_port_t requestor_port, mach_port_t *subset_port)
{
	return raw_bootstrap_subset(bp, requestor_port, subset_port);
}

kern_return_t
bootstrap_unprivileged(mach_port_t bp, mach_port_t *unpriv_port)
{
	return raw_bootstrap_unprivileged(bp, unpriv_port);
}

kern_return_t
bootstrap_getsocket(mach_port_t bp, name_t sockpath)
{
	return raw_bootstrap_getsocket(bp, sockpath);
}

kern_return_t
bootstrap_parent(mach_port_t bp, mach_port_t *parent_port)
{
	return raw_bootstrap_parent(bp, parent_port);
}

kern_return_t
bootstrap_register(mach_port_t bp, name_t service_name, mach_port_t sp)
{
	return raw_bootstrap_register(bp, service_name, sp);
}

kern_return_t
bootstrap_create_service(mach_port_t bp, name_t service_name, mach_port_t *sp)
{
	return raw_bootstrap_create_service(bp, service_name, sp);
}

kern_return_t
bootstrap_check_in(mach_port_t bp, name_t service_name, mach_port_t *sp)
{
	return raw_bootstrap_check_in(bp, service_name, sp);
}

kern_return_t
bootstrap_look_up(mach_port_t bp, name_t service_name, mach_port_t *sp)
{
	return raw_bootstrap_look_up(bp, service_name, sp);
}

kern_return_t
bootstrap_look_up_array(mach_port_t bp,
		name_array_t names, mach_msg_type_number_t name_cnt,
		mach_port_array_t *ports, mach_msg_type_number_t *port_cnt,
		boolean_t *all)
{
	unsigned int i;
	kern_return_t r;

	if (name_cnt > BOOTSTRAP_MAX_LOOKUP_COUNT)
		return BOOTSTRAP_BAD_COUNT;

	*port_cnt = name_cnt;

	r = vm_allocate(mach_task_self(), (vm_address_t *)&ports, name_cnt * sizeof(mach_port_t), true);

	if (r != KERN_SUCCESS)
		return r;

	*all = true;

	for (i = 0; i < name_cnt; i++) {
		if (bootstrap_look_up(bp, names[i], &((*ports)[i])) == BOOTSTRAP_SUCCESS)
			continue;
		*all = false;
		ports[i] = MACH_PORT_NULL;
	}

	return BOOTSTRAP_SUCCESS;
}

kern_return_t
bootstrap_status(mach_port_t bp, name_t service_name, bootstrap_status_t *service_active)
{
	mach_port_t p;

	if (bootstrap_check_in(bp, service_name, &p) == BOOTSTRAP_SUCCESS) {
		mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
		*service_active = BOOTSTRAP_STATUS_ON_DEMAND;
		if (bootstrap_unprivileged(bp, &p) == BOOTSTRAP_SUCCESS) {
			if (bp == p)
				*service_active = BOOTSTRAP_STATUS_INACTIVE;
			mach_port_deallocate(mach_task_self(), p);
		}
		return BOOTSTRAP_SUCCESS;
	} else if (bootstrap_look_up(bp, service_name, &p) == BOOTSTRAP_SUCCESS) {
		mach_port_deallocate(mach_task_self(), p);
		*service_active = BOOTSTRAP_STATUS_ACTIVE;
		return BOOTSTRAP_SUCCESS;
	}

	return BOOTSTRAP_UNKNOWN_SERVICE;
}

kern_return_t
bootstrap_info(mach_port_t bp,
		name_array_t *service_names, mach_msg_type_number_t *service_namesCnt,
		bootstrap_status_array_t *service_active, mach_msg_type_number_t *service_activeCnt)
{
	return raw_bootstrap_info(bp, service_names, service_namesCnt,
			service_active, service_activeCnt);
}

const char *
bootstrap_strerror(kern_return_t r)
{
	switch (r) {
	case BOOTSTRAP_SUCCESS:
		return "Success";
	case BOOTSTRAP_NOT_PRIVILEGED:
		return "Permission denied";
	case BOOTSTRAP_NAME_IN_USE:
	case BOOTSTRAP_SERVICE_ACTIVE:
		return "Service name already exists";
	case BOOTSTRAP_UNKNOWN_SERVICE:
		return "Unknown service name";
	case BOOTSTRAP_BAD_COUNT:
		return "Too many lookups were requested in one request";
	case BOOTSTRAP_NO_MEMORY:
		return "Out of memory";
	default:
		return mach_error_string(r);
	}
}
