#ifndef _VPROC_INTERNAL_H_
#define _VPROC_INTERNAL_H_
/*
 * Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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

#include <mach/mach.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <stdarg.h>
#include "liblaunch_public.h"
#include "libbootstrap_public.h"
#include "libvproc_public.h"

typedef char * _internal_string_t;
typedef char * logmsg_t;
typedef pid_t * pid_array_t;
typedef mach_port_t vproc_mig_t;

#ifdef protocol_vproc_MSG_COUNT
/* HACK */
#include "launchd_core_logic.h"
#endif

#define VPROC_ERR_TRY_PER_USER	1099

#pragma GCC visibility push(default)

vproc_err_t _vprocmgr_init(const char *session_type);
vproc_err_t _vproc_post_fork_ping(void);

#define SPAWN_HAS_PATH			0x0001
#define SPAWN_HAS_WDIR			0x0002
#define SPAWN_HAS_UMASK			0x0004
#define SPAWN_WANTS_WAIT4DEBUGGER	0x0008

kern_return_t
_vproc_grab_subset(mach_port_t bp, mach_port_t *reqport, mach_port_t *rcvright, launch_data_t *outval,
		mach_port_array_t *ports, mach_msg_type_number_t *portCnt);

kern_return_t _vprocmgr_getsocket(name_t);


struct logmsg_s {
	STAILQ_ENTRY(logmsg_s) sqe;
	struct timeval when;
	pid_t from_pid;
	pid_t about_pid;
	uid_t sender_uid;
	gid_t sender_gid;
	int err_num;
	int pri;
	const char *from_name;
	const char *about_name;
	const char *session_name;
	const char *msg;
	size_t obj_sz;
	char data[0];
};


void _vproc_logv(int pri, int err, const char *msg, va_list ap);
vproc_err_t _vprocmgr_log_forward(mach_port_t mp, void *data, size_t len);


kern_return_t
bootstrap_info(
		mach_port_t bp,
		name_array_t *service_names,
		mach_msg_type_number_t *service_namesCnt,
		bootstrap_status_array_t *service_active,
		mach_msg_type_number_t *service_activeCnt);

#pragma GCC visibility pop

#endif
