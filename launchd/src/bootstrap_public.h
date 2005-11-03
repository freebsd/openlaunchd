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
/*
 * bootstrap -- fundamental service initiator and port server
 * Mike DeMoney, NeXT, Inc.
 * Copyright, 1990.  All rights reserved.
 */

#ifndef _BOOTSTRAP_DEFS_
#define	_BOOTSTRAP_DEFS_
#include <mach/std_types.h>
#include <mach/message.h>
#include <sys/types.h>
#include <stdbool.h>

#define	BOOTSTRAP_MAX_NAME_LEN			128
#define	BOOTSTRAP_MAX_CMD_LEN			512

typedef char name_t[BOOTSTRAP_MAX_NAME_LEN];
typedef char cmd_t[BOOTSTRAP_MAX_CMD_LEN];
typedef name_t *name_array_t;
typedef int bootstrap_status_t;
typedef bootstrap_status_t *bootstrap_status_array_t;

typedef boolean_t *bool_array_t;

#define	BOOTSTRAP_MAX_LOOKUP_COUNT		20

#define	BOOTSTRAP_SUCCESS			0
#define	BOOTSTRAP_NOT_PRIVILEGED		1100
#define	BOOTSTRAP_NAME_IN_USE			1101
#define	BOOTSTRAP_UNKNOWN_SERVICE		1102
#define	BOOTSTRAP_SERVICE_ACTIVE		1103
#define	BOOTSTRAP_BAD_COUNT			1104
#define	BOOTSTRAP_NO_MEMORY			1105

#define BOOTSTRAP_STATUS_INACTIVE		0
#define BOOTSTRAP_STATUS_ACTIVE			1
#define BOOTSTRAP_STATUS_ON_DEMAND		2

extern mach_port_t bootstrap_port;

kern_return_t bootstrap_create_server(
		mach_port_t bp,
		cmd_t server_cmd,
		uid_t server_uid,
		boolean_t on_demand,
		mach_port_t *server_port);

kern_return_t bootstrap_subset(
		mach_port_t bp,
		mach_port_t requestor_port,
		mach_port_t *subset_port);

kern_return_t bootstrap_unprivileged(
		mach_port_t bp,
		mach_port_t *unpriv_port);

kern_return_t bootstrap_parent(
		mach_port_t bp,
		mach_port_t *parent_port);

kern_return_t bootstrap_register(
		mach_port_t bp,
		name_t service_name,
		mach_port_t sp);

kern_return_t bootstrap_create_service(
		mach_port_t bp,
		name_t service_name,
		mach_port_t *sp);

kern_return_t bootstrap_check_in(
		mach_port_t bp,
		name_t service_name,
		mach_port_t *sp);

kern_return_t bootstrap_look_up(
		mach_port_t bp,
		name_t service_name,
		mach_port_t *sp);

kern_return_t bootstrap_look_up_array(
		mach_port_t bp,
		name_array_t service_names,
		mach_msg_type_number_t service_namesCnt,
		mach_port_array_t *sps,
		mach_msg_type_number_t *service_portsCnt,
		boolean_t *all_services_known);

kern_return_t bootstrap_status(
		mach_port_t bp,
		name_t service_name,
		bootstrap_status_t *service_active);

kern_return_t bootstrap_info(
		mach_port_t bp,
		name_array_t *service_names,
		mach_msg_type_number_t *service_namesCnt,
		name_array_t *server_names,
		mach_msg_type_number_t *server_namesCnt,
		bootstrap_status_array_t *service_active,
		mach_msg_type_number_t *service_activeCnt);



#endif
