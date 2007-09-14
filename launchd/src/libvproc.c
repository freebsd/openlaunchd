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
#include <syslog.h>
#include <pthread.h>

#include "liblaunch_public.h"
#include "liblaunch_private.h"
#include "liblaunch_internal.h"

#include "protocol_vproc.h"

#include "reboot2.h"

static mach_port_t get_root_bootstrap_port(void);

static int64_t cached_pid = -1;

kern_return_t
_vproc_grab_subset(mach_port_t bp, mach_port_t *reqport, mach_port_t *rcvright, launch_data_t *outval,
		mach_port_array_t *ports, mach_msg_type_number_t *portCnt)
{
	mach_msg_type_number_t outdata_cnt;
	vm_offset_t outdata = 0;
	size_t data_offset = 0;
	launch_data_t out_obj;
	kern_return_t kr;

	if ((kr = vproc_mig_take_subset(bp, reqport, rcvright, &outdata, &outdata_cnt, ports, portCnt))) {
		goto out;
	}

	if ((out_obj = launch_data_unpack((void *)outdata, outdata_cnt, NULL, 0, &data_offset, NULL))) {
		*outval = launch_data_copy(out_obj);
	} else {
		kr = 1;
	}

out:
	if (outdata) {
		mig_deallocate(outdata, outdata_cnt);
	}

	return kr;
}

vproc_err_t
_vproc_post_fork_ping(void)
{
	return vproc_mig_post_fork_ping(bootstrap_port, mach_task_self()) == 0 ? NULL : _vproc_post_fork_ping;
}

static void
setup_env_hack(const launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	setenv(key, launch_data_get_string(obj), 1);
}

vproc_err_t
_vprocmgr_init(const char *session_type)
{
	if (vproc_mig_move_subset(bootstrap_port, MACH_PORT_NULL, (char *)session_type) == 0) {
		return NULL;
	}

	return (vproc_err_t)_vprocmgr_init;
}

vproc_err_t
_vprocmgr_move_subset_to_user(uid_t target_user, const char *session_type)
{
	launch_data_t output_obj;
	kern_return_t kr = 0;
	bool is_bkgd = (strcmp(session_type, VPROCMGR_SESSION_BACKGROUND) == 0);
	int64_t ldpid, lduid;

	if (vproc_swap_integer(NULL, VPROC_GSK_MGR_PID, 0, &ldpid) != 0) {
		return (vproc_err_t)_vprocmgr_move_subset_to_user;
	}

	if (vproc_swap_integer(NULL, VPROC_GSK_MGR_UID, 0, &lduid) != 0) {
		return (vproc_err_t)_vprocmgr_move_subset_to_user;
	}

	if (!is_bkgd && ldpid != 1) {
		if (lduid == getuid()) {
			return NULL;
		}
		/*
		 * Not all sessions can be moved.
		 * We should clean up this mess someday.
		 */
		return (vproc_err_t)_vprocmgr_move_subset_to_user;
	}

	if (is_bkgd || target_user) {
		mach_port_t puc = 0, rootbs = get_root_bootstrap_port();

		if (vproc_mig_lookup_per_user_context(rootbs, target_user, &puc) != 0) {
			return (vproc_err_t)_vprocmgr_move_subset_to_user;
		}

		if (is_bkgd) {
			task_set_bootstrap_port(mach_task_self(), puc);
			mach_port_deallocate(mach_task_self(), bootstrap_port);
			bootstrap_port = puc;
		} else {
			kr = vproc_mig_move_subset(puc, bootstrap_port, (char *)session_type);
			mach_port_deallocate(mach_task_self(), puc);
		}
	} else {
		kr = _vprocmgr_init(session_type) ? 1 : 0;
	}

	cached_pid = -1;

	if (kr) {
		return (vproc_err_t)_vprocmgr_move_subset_to_user;
	}

	/* XXX We need to give 'nohup' a better API after Leopard ships */
	if (getprogname() && strcmp(getprogname(), "nohup") != 0) {
		if (vproc_swap_complex(NULL, VPROC_GSK_ENVIRONMENT, NULL, &output_obj) == NULL) {
			if (launch_data_get_type(output_obj) == LAUNCH_DATA_DICTIONARY) {
				launch_data_dict_iterate(output_obj, setup_env_hack, NULL);
				launch_data_free(output_obj);
			}
		}
	}

	return _vproc_post_fork_ping();
}


pid_t
_spawn_via_launchd(const char *label, const char *const *argv, const struct spawn_via_launchd_attr *spawn_attrs, int struct_version)
{
	size_t i, good_enough_size = 10*1024*1024;
	mach_msg_type_number_t indata_cnt = 0;
	vm_offset_t indata = 0;
	mach_port_t obsvr_port = MACH_PORT_NULL;
	launch_data_t tmp, tmp_array, in_obj;
	const char *const *tmpp;
	kern_return_t kr = 1;
	void *buf = NULL;
	pid_t p = -1;

	if ((in_obj = launch_data_alloc(LAUNCH_DATA_DICTIONARY)) == NULL) {
		goto out;
	}

	if ((tmp = launch_data_new_string(label)) == NULL) {
		goto out;
	}

	launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_LABEL);

	if ((tmp_array = launch_data_alloc(LAUNCH_DATA_ARRAY)) == NULL) {
		goto out;
	}

	for (i = 0; *argv; i++, argv++) {
		tmp = launch_data_new_string(*argv);
		if (tmp == NULL) {
			goto out;
		}

		launch_data_array_set_index(tmp_array, tmp, i);
	}

	launch_data_dict_insert(in_obj, tmp_array, LAUNCH_JOBKEY_PROGRAMARGUMENTS);

	if (spawn_attrs) switch (struct_version) {
	case 2:
		if (spawn_attrs->spawn_quarantine) {
			char qbuf[QTN_SERIALIZED_DATA_MAX];
			size_t qbuf_sz = QTN_SERIALIZED_DATA_MAX;

			if (qtn_proc_to_data(spawn_attrs->spawn_quarantine, qbuf, &qbuf_sz) == 0) {
				tmp = launch_data_new_opaque(qbuf, qbuf_sz);
				launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_QUARANTINEDATA);
			}
		}

		if (spawn_attrs->spawn_seatbelt_profile) {
			tmp = launch_data_new_string(spawn_attrs->spawn_seatbelt_profile);
			launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_SANDBOXPROFILE);
		}

		if (spawn_attrs->spawn_seatbelt_flags) {
			tmp = launch_data_new_integer(*spawn_attrs->spawn_seatbelt_flags);
			launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_SANDBOXFLAGS);
		}

		/* fall through */
	case 1:
		if (spawn_attrs->spawn_binpref) {
			tmp_array = launch_data_alloc(LAUNCH_DATA_ARRAY);
			for (i = 0; i < spawn_attrs->spawn_binpref_cnt; i++) {
				tmp = launch_data_new_integer(spawn_attrs->spawn_binpref[i]);
				launch_data_array_set_index(tmp_array, tmp, i);
			}
			launch_data_dict_insert(in_obj, tmp_array, LAUNCH_JOBKEY_BINARYORDERPREFERENCE);
		}
		/* fall through */
	case 0:
		if (spawn_attrs->spawn_flags & SPAWN_VIA_LAUNCHD_STOPPED) {
			tmp = launch_data_new_bool(true);
			launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_WAITFORDEBUGGER);
		}

		if (spawn_attrs->spawn_env) {
			launch_data_t tmp_dict = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

			for (tmpp = spawn_attrs->spawn_env; *tmpp; tmpp++) {
				char *eqoff, tmpstr[strlen(*tmpp) + 1];

				strcpy(tmpstr, *tmpp);

				eqoff = strchr(tmpstr, '=');

				if (!eqoff) {
					goto out;
				}
				
				*eqoff = '\0';
				
				launch_data_dict_insert(tmp_dict, launch_data_new_string(eqoff + 1), tmpstr);
			}

			launch_data_dict_insert(in_obj, tmp_dict, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES);
		}

		if (spawn_attrs->spawn_path) {
			tmp = launch_data_new_string(spawn_attrs->spawn_path);
			launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_PROGRAM);
		}

		if (spawn_attrs->spawn_chdir) {
			tmp = launch_data_new_string(spawn_attrs->spawn_chdir);
			launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_WORKINGDIRECTORY);
		}

		if (spawn_attrs->spawn_umask) {
			tmp = launch_data_new_integer(*spawn_attrs->spawn_umask);
			launch_data_dict_insert(in_obj, tmp, LAUNCH_JOBKEY_UMASK);
		}

		break;
	default:
		break;
	}

	if (!(buf = malloc(good_enough_size))) {
		goto out;
	}

	if ((indata_cnt = launch_data_pack(in_obj, buf, good_enough_size, NULL, NULL)) == 0) {
		goto out;
	}

	indata = (vm_offset_t)buf;

	kr = vproc_mig_spawn(bootstrap_port, indata, indata_cnt, &p, &obsvr_port);

	if (kr == VPROC_ERR_TRY_PER_USER) {
		mach_port_t puc;

		if (vproc_mig_lookup_per_user_context(bootstrap_port, 0, &puc) == 0) {
			kr = vproc_mig_spawn(puc, indata, indata_cnt, &p, &obsvr_port);
			mach_port_deallocate(mach_task_self(), puc);
		}
	}

out:
	if (in_obj) {
		launch_data_free(in_obj);
	}

	if (buf) {
		free(buf);
	}

	switch (kr) {
	case BOOTSTRAP_SUCCESS:
		if (spawn_attrs && spawn_attrs->spawn_observer_port) {
			*spawn_attrs->spawn_observer_port = obsvr_port;
		} else {
			mach_port_deallocate(mach_task_self(), obsvr_port);
		}
		return p;
	case BOOTSTRAP_NOT_PRIVILEGED:
		errno = EPERM; break;
	case BOOTSTRAP_NO_MEMORY:
		errno = ENOMEM; break;
	case BOOTSTRAP_NAME_IN_USE:
		errno = EEXIST; break;
	case 1:
		errno = EIO; break;
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

	if (vproc_swap_integer(NULL, VPROC_GSK_LAST_EXIT_STATUS, 0, &val) == 0) {
		*wstatus = (int)val;
		return NULL;
	}

	return (vproc_err_t)_vproc_get_last_exit_status;
}

vproc_err_t
_vproc_send_signal_by_label(const char *label, int sig)
{
	if (vproc_mig_send_signal(bootstrap_port, (char *)label, sig) == 0) {
		return NULL;
	}

	return _vproc_send_signal_by_label;
}

vproc_err_t
_vprocmgr_log_forward(mach_port_t mp, void *data, size_t len)
{
	if (vproc_mig_log_forward(mp, (vm_offset_t)data, len) == 0) {
		return NULL;
	}

	return _vprocmgr_log_forward;
}

vproc_err_t
_vprocmgr_log_drain(vproc_t vp __attribute__((unused)), pthread_mutex_t *mutex, _vprocmgr_log_drain_callback_t func)
{
	mach_msg_type_number_t outdata_cnt, tmp_cnt;
	vm_offset_t outdata = 0;
	struct logmsg_s *lm;

	if (!func) {
		return _vprocmgr_log_drain;
	}

	if (vproc_mig_log_drain(bootstrap_port, &outdata, &outdata_cnt) != 0) {
		return _vprocmgr_log_drain;
	}

	tmp_cnt = outdata_cnt;

	if (mutex) {
		pthread_mutex_lock(mutex);
	}

	for (lm = (struct logmsg_s *)outdata; tmp_cnt > 0; lm = ((void *)lm + lm->obj_sz)) {
		lm->from_name += (size_t)lm;
		lm->about_name += (size_t)lm;
		lm->msg += (size_t)lm;
		lm->session_name += (size_t)lm;

		func(&lm->when, lm->from_pid, lm->about_pid, lm->sender_uid, lm->sender_gid, lm->pri,
				lm->from_name, lm->about_name, lm->session_name, lm->msg);

		tmp_cnt -= lm->obj_sz;
	}

	if (mutex) {
		pthread_mutex_unlock(mutex);
	}

	if (outdata) {
		mig_deallocate(outdata, outdata_cnt);
	}

	return NULL;
}

vproc_err_t
vproc_swap_integer(vproc_t vp __attribute__((unused)), vproc_gsk_t key, int64_t *inval, int64_t *outval)
{
	static int64_t cached_is_managed = -1;
	int64_t dummyval = 0;

	switch (key) {
	case VPROC_GSK_MGR_PID:
		if (cached_pid != -1 && outval) {
			*outval = cached_pid;
			return NULL;
		}
		break;
	case VPROC_GSK_IS_MANAGED:
		if (cached_is_managed != -1 && outval) {
			*outval = cached_is_managed;
			return NULL;
		}
		break;
	default:
		break;
	}

	if (vproc_mig_swap_integer(bootstrap_port, inval ? key : 0, outval ? key : 0, inval ? *inval : 0, outval ? outval : &dummyval) == 0) {
		switch (key) {
		case VPROC_GSK_MGR_PID:
			cached_pid = outval ? *outval : dummyval;
			break;
		case VPROC_GSK_IS_MANAGED:
			cached_is_managed = outval ? *outval : dummyval;
			break;
		default:
			break;
		}
		return NULL;
	}

	return (vproc_err_t)vproc_swap_integer;
}

mach_port_t
get_root_bootstrap_port(void)
{
	mach_port_t parent_port = 0;
	mach_port_t previous_port = 0;

	do {
		if (previous_port) {
			if (previous_port != bootstrap_port) {
				mach_port_deallocate(mach_task_self(), previous_port);
			}
			previous_port = parent_port;
		} else {
			previous_port = bootstrap_port;
		}

		if (bootstrap_parent(previous_port, &parent_port) != 0) {
			return MACH_PORT_NULL;
		}

	} while (parent_port != previous_port);

	return parent_port;
}

vproc_err_t
vproc_swap_complex(vproc_t vp __attribute__((unused)), vproc_gsk_t key, launch_data_t inval, launch_data_t *outval)
{
	size_t data_offset = 0, good_enough_size = 10*1024*1024;
	mach_msg_type_number_t indata_cnt = 0, outdata_cnt;
	vm_offset_t indata = 0, outdata = 0;
	launch_data_t out_obj;
	void *rval = vproc_swap_complex;
	void *buf = NULL;

	if (inval) {
		if (!(buf = malloc(good_enough_size))) {
			goto out;
		}

		if ((indata_cnt = launch_data_pack(inval, buf, good_enough_size, NULL, NULL)) == 0) {
			goto out;
		}

		indata = (vm_offset_t)buf;
	}

	if (vproc_mig_swap_complex(bootstrap_port, inval ? key : 0, outval ? key : 0, indata, indata_cnt, &outdata, &outdata_cnt) != 0) {
		goto out;
	}

	if (outval) {
		if (!(out_obj = launch_data_unpack((void *)outdata, outdata_cnt, NULL, 0, &data_offset, NULL))) {
			goto out;
		}

		if (!(*outval = launch_data_copy(out_obj))) {
			goto out;
		}
	}

	rval = NULL;
out:
	if (buf) {
		free(buf);
	}

	if (outdata) {
		mig_deallocate(outdata, outdata_cnt);
	}

	return rval;
}

void *
reboot2(uint64_t flags)
{
	if (vproc_mig_reboot2(get_root_bootstrap_port(), flags) == 0) {
		return NULL;
	}

	return reboot2;
}

vproc_err_t
_vproc_set_global_on_demand(bool state)
{
	int64_t val = state ? ~0 : 0;

	if (vproc_swap_integer(NULL, VPROC_GSK_GLOBAL_ON_DEMAND, &val, NULL) == 0) {
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
