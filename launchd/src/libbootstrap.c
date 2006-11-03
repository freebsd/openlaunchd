/*
 * Copyright (c) 1999-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

#include "config.h"
#include "libbootstrap_public.h"

#include "libvproc_public.h"
#include "libvproc_private.h"

#include <mach/mach.h>
#include <mach/vm_map.h>

#include "protocol_vproc.h"

kern_return_t
bootstrap_create_server(mach_port_t bp, cmd_t server_cmd, uid_t server_uid, boolean_t on_demand, mach_port_t *server_port)
{
	return vproc_mig_create_server(bp, server_cmd, server_uid, on_demand, server_port);
}

kern_return_t
bootstrap_subset(mach_port_t bp, mach_port_t requestor_port, mach_port_t *subset_port)
{
	return vproc_mig_subset(bp, requestor_port, subset_port);
}

kern_return_t
bootstrap_unprivileged(mach_port_t bp, mach_port_t *unpriv_port)
{
	kern_return_t kr;

	*unpriv_port = MACH_PORT_NULL;

	kr = mach_port_mod_refs(mach_task_self(), bp, MACH_PORT_RIGHT_SEND, 1);

	if (kr == KERN_SUCCESS) {
		*unpriv_port = bp;
	}

	return kr;
}

kern_return_t
bootstrap_parent(mach_port_t bp, mach_port_t *parent_port)
{
	return vproc_mig_parent(bp, parent_port);
}

kern_return_t
bootstrap_register(mach_port_t bp, name_t service_name, mach_port_t sp)
{
	kern_return_t kr = vproc_mig_register(bp, service_name, sp);

	if (kr == VPROC_ERR_TRY_PER_USER) {
		mach_port_t puc;

		if (vproc_mig_lookup_per_user_context(bp, 0, &puc) == 0) {
			kr = vproc_mig_register(puc, service_name, sp);
			mach_port_deallocate(mach_task_self(), puc);
		}
	}

	return kr;
}

kern_return_t
bootstrap_create_service(mach_port_t bp, name_t service_name, mach_port_t *sp)
{
	return vproc_mig_create_service(bp, service_name, sp);
}

kern_return_t
bootstrap_check_in(mach_port_t bp, name_t service_name, mach_port_t *sp)
{
	return vproc_mig_check_in(bp, service_name, sp);
}

kern_return_t
bootstrap_look_up(mach_port_t bp, name_t service_name, mach_port_t *sp)
{
	kern_return_t kr;
	mach_port_t puc;

	if ((kr = vproc_mig_look_up(bp, service_name, sp)) != VPROC_ERR_TRY_PER_USER) {
		return kr;
	}

	if ((kr = vproc_mig_lookup_per_user_context(bp, 0, &puc)) != 0) {
		return kr;
	}

	kr = vproc_mig_look_up(puc, service_name, sp);
	mach_port_deallocate(mach_task_self(), puc);

	return kr;
}

kern_return_t
bootstrap_status(mach_port_t bp, name_t service_name, bootstrap_status_t *service_active)
{
	mach_port_t p;

	if (bootstrap_check_in(bp, service_name, &p) == BOOTSTRAP_SUCCESS) {
		mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
		*service_active = BOOTSTRAP_STATUS_ON_DEMAND;
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
	return vproc_mig_info(bp, service_names, service_namesCnt,
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
