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
#include "libvproc_public.h"
#include "libvproc_private.h"
#include "libvproc_internal.h"

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "liblaunch_public.h"
#include "liblaunch_private.h"

#include "protocol_vproc.h"

#include "poweroff.h"

kern_return_t
_vproc_grab_subset(mach_port_t bp, mach_port_t *reqport, mach_port_t *rcvright,
		name_array_t *service_names, mach_msg_type_number_t *service_namesCnt,
		mach_port_array_t *ports, mach_msg_type_number_t *portCnt)
{
	return vproc_mig_take_subset(bp, reqport, rcvright, service_names, service_namesCnt, ports, portCnt);
}

vproc_err_t
_vproc_move_subset_to_user(void)
{
	kern_return_t kr = 1;
	mach_port_t puc = 0, which_port = bootstrap_port;

	if ((getuid() || geteuid()) && vproc_mig_lookup_per_user_context(bootstrap_port, 0, &puc) == 0) {
		which_port = puc;
	}

	kr = vproc_mig_move_subset_to_user(which_port, bootstrap_port);

	if (puc) {
		mach_port_deallocate(mach_task_self(), puc);
	}

	return kr == 0 ? NULL : (vproc_err_t)_vproc_move_subset_to_user;
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
	binpref_t bin_pref;
	size_t binpref_cnt = 0, binpref_max = sizeof(bin_pref) / sizeof(bin_pref[0]);
	pid_t p = -1;
	mode_t u_mask = CMASK;
	mach_port_t obsvr_port = MACH_PORT_NULL;

	memset(&bin_pref, 0, sizeof(bin_pref));

	for (tmpp = argv; *tmpp; tmpp++) {
		argc++;
		len = strlen(*tmpp) + 1;
		buf = reallocf(buf, buf_len + len);
		strcpy(buf + buf_len, *tmpp);
		buf_len += len;
	}

	if (spawn_attrs) switch (struct_version) {
	case 1:
		if (spawn_attrs->spawn_binpref) {
			if (spawn_attrs->spawn_binpref_cnt < binpref_max) {
				binpref_max = spawn_attrs->spawn_binpref_cnt;
			}

			for (; binpref_cnt < binpref_max; binpref_cnt++) {
				bin_pref[binpref_cnt] = spawn_attrs->spawn_binpref[binpref_cnt];
			}
		}

	case 0:
		if (spawn_attrs->spawn_flags & SPAWN_VIA_LAUNCHD_STOPPED) {
			flags |= SPAWN_WANTS_WAIT4DEBUGGER;
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

	kr = vproc_mig_spawn(bootstrap_port, buf, buf_len, argc, envc, flags, u_mask, bin_pref, binpref_cnt, &p, &obsvr_port);

	if (kr == VPROC_ERR_TRY_PER_USER) {
		mach_port_t puc;

		if (vproc_mig_lookup_per_user_context(bootstrap_port, 0, &puc) == 0) {
			kr = vproc_mig_spawn(puc, buf, buf_len, argc, envc, flags, u_mask, bin_pref, binpref_cnt, &p, &obsvr_port);
			mach_port_deallocate(mach_task_self(), puc);
		}
	}

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
mpm_wait(mach_port_t ajob __attribute__((unused)), int *wstatus)
{
	return vproc_mig_wait(ajob, wstatus);
}

kern_return_t
mpm_uncork_fork(mach_port_t ajob)
{
	return vproc_mig_uncork_fork(ajob);
}

kern_return_t
_vprocmgr_getsocket(name_t sockpath)
{
	return vproc_mig_getsocket(bootstrap_port, sockpath);
}

vproc_err_t
_vproc_get_last_exit_status(int *wstatus)
{
	int64_t val;

	if (vproc_mig_get_integer(bootstrap_port, LAST_EXIT_STATUS, &val) == 0) {
		*wstatus = (int)val;
		return NULL;
	}

	return (vproc_err_t)_vproc_get_last_exit_status;
}

vproc_err_t
__vproc_tag_loginwindow_context(void)
{
	if (vproc_mig_set_integer(bootstrap_port, GSK_LOGINWINDOW_CONTEXT, 1) == 0) {
		return NULL;
	}

	return (vproc_err_t)__vproc_tag_loginwindow_context;
}

void *
poweroff(uint64_t flags)
{
	mach_port_t parent_port = 0;
	mach_port_t previous_port = 0;

	do {
		if (previous_port) {
			mach_port_deallocate(mach_task_self(), previous_port);
			previous_port = parent_port;
		} else {
			previous_port = bootstrap_port;
		}

		if (bootstrap_parent(previous_port, &parent_port) != 0) {
			goto out_bad;
		}

	} while (parent_port != previous_port);

	if (vproc_mig_poweroff(parent_port, flags) == 0) {
		return NULL;
	}

out_bad:
	return poweroff;
}

vproc_err_t
_vproc_set_global_on_demand(bool state)
{
	int64_t val = state ? ~0 : 0;

	if (vproc_mig_set_integer(bootstrap_port, GLOBAL_ON_DEMAND, val) == 0) {
		return NULL;
	}

	return (vproc_err_t)_vproc_set_global_on_demand;
}

void
_vproc_logv(int pri, int err, const char *msg, va_list ap)
{
	char flat_msg[3000];

	vsnprintf(flat_msg, sizeof(flat_msg), msg, ap);

	vproc_mig_log(bootstrap_port, pri, err, flat_msg);
}

void
_vproc_log(int pri, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	_vproc_logv(pri, 0, msg, ap);
	va_end(ap);
}

void
_vproc_log_error(int pri, const char *msg, ...)
{
	int saved_errno = errno;
	va_list ap;

	va_start(ap, msg);
	_vproc_logv(pri, saved_errno, msg, ap);
	va_end(ap);
}
