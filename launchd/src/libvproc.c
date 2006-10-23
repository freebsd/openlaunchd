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

#include <mach/mach.h>
#include <mach/vm_map.h>

#include "bootstrap_public.h"
#include "vproc_priv.h"
#include "launch.h"
#include "launch_priv.h"

#include "protocol_vproc.h"

#include <sys/param.h>
#include <stdlib.h>
#include <errno.h>

kern_return_t
_launchd_to_launchd(mach_port_t bp, mach_port_t *reqport, mach_port_t *rcvright,
		name_array_t *service_names, mach_msg_type_number_t *service_namesCnt,
		mach_port_array_t *ports, mach_msg_type_number_t *portCnt)
{
	return vproc_mig_transfer_subset(bp, reqport, rcvright, service_names, service_namesCnt, ports, portCnt);
}

pid_t
_spawn_via_launchd(const char *label, const char *const *argv, const struct spawn_via_launchd_attr *spawn_attrs, int struct_version)
{
	kern_return_t kr;
	const char *const *tmpp;
	size_t len, buf_len = strlen(label) + 1;
	char *buf = strdup(label);
	uint64_t flags = 0;
	uint32_t argc = 0;
	uint32_t envc = 0;
	pid_t p = -1;
	mode_t u_mask = CMASK;
	mach_port_t obsvr_port = MACH_PORT_NULL;

	for (tmpp = argv; *tmpp; tmpp++) {
		argc++;
		len = strlen(*tmpp) + 1;
		buf = reallocf(buf, buf_len + len);
		strcpy(buf + buf_len, *tmpp);
		buf_len += len;
	}

	if (spawn_attrs) switch (struct_version) {
	case 0:
		if (spawn_attrs->spawn_flags & SPAWN_VIA_LAUNCHD_STOPPED) {
			flags |= SPAWN_WANTS_WAIT4DEBUGGER;
		}
		if (spawn_attrs->spawn_flags & SPAWN_VIA_LAUNCHD_FORCE_PPC) {
			flags |= SPAWN_WANTS_FORCE_PPC;
		}

		if (spawn_attrs->spawn_env) {
			for (tmpp = spawn_attrs->spawn_env; *tmpp; tmpp++) {
				envc++;
				len = strlen(*tmpp) + 1;
				buf = reallocf(buf, buf_len + len);
				strcpy(buf + buf_len, *tmpp);
				buf_len += len;
			}
		}

		if (spawn_attrs->spawn_path) {
			flags |= SPAWN_HAS_PATH;
			len = strlen(spawn_attrs->spawn_path) + 1;
			buf = reallocf(buf, buf_len + len);
			strcpy(buf + buf_len, spawn_attrs->spawn_path);
			buf_len += len;
		}

		if (spawn_attrs->spawn_chdir) {
			flags |= SPAWN_HAS_WDIR;
			len = strlen(spawn_attrs->spawn_chdir) + 1;
			buf = reallocf(buf, buf_len + len);
			strcpy(buf + buf_len, spawn_attrs->spawn_chdir);
			buf_len += len;
		}

		if (spawn_attrs->spawn_umask) {
			flags |= SPAWN_HAS_UMASK;
			u_mask = *spawn_attrs->spawn_umask;
		}

		break;
	default:
		break;
	}

	kr = vproc_mig_spawn(bootstrap_port, buf, buf_len, argc, envc, flags, u_mask, &p, &obsvr_port);

	free(buf);

	if (kr == BOOTSTRAP_SUCCESS) {
		if (spawn_attrs && spawn_attrs->spawn_observer_port) {
			*spawn_attrs->spawn_observer_port = obsvr_port;
		} else {
			mach_port_deallocate(mach_task_self(), obsvr_port);
		}
		return p;
	}

	switch (kr) {
	case BOOTSTRAP_NOT_PRIVILEGED:
		errno = EPERM; break;
	case BOOTSTRAP_NO_MEMORY:
		errno = ENOMEM; break;
	default:
		errno = EINVAL; break;
	}
	return -1;
}

kern_return_t
mpm_wait(mach_port_t ajob, int *wstatus)
{
	return vproc_mig_wait(ajob, wstatus);
}

kern_return_t
mpm_uncork_fork(mach_port_t ajob)
{
	return vproc_mig_uncork_fork(ajob);
}

kern_return_t
vprocmgr_getsocket(mach_port_t bp, name_t sockpath)
{
	return vproc_mig_getsocket(bp, sockpath);
}
