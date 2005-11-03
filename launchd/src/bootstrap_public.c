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
#include "bootstrap.h"

/* Libc initializes this for now */
mach_port_t bootstrap_port = MACH_PORT_NULL;

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
	return raw_bootstrap_status(bp, service_name, service_active);
}

kern_return_t
bootstrap_info(mach_port_t bp,
		name_array_t *service_names, mach_msg_type_number_t *service_namesCnt,
		name_array_t *server_names, mach_msg_type_number_t *server_namesCnt,
		bootstrap_status_array_t *service_active, mach_msg_type_number_t *service_activeCnt)
{
	return raw_bootstrap_info(bp, service_names, service_namesCnt,
			server_names, server_namesCnt,
			service_active, service_activeCnt);
}
