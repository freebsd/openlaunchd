/*
 * Copyright (c) 1999-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * bootstrap -- fundamental service initiator and port server
 * Mike DeMoney, NeXT, Inc.
 * Copyright, 1990.  All rights reserved.
 *
 * bootstrap.c -- implementation of bootstrap main service loop
 */

static const char *const __rcs_file_version__ = "$Revision$";

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
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>

#include "launchd_core_logic.h"
#include "bootstrap_public.h"
#include "bootstrap_private.h"
#include "bootstrap.h"
#include "bootstrapServer.h"
#include "launchd.h"
#include "launchd_runtime.h"
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
static void audit_token_to_launchd_cred(audit_token_t au_tok, struct ldcred *ldc);

mach_port_t inherited_bootstrap_port = MACH_PORT_NULL;

static bool trusted_client_check(job_t j, struct ldcred *ldc);

void
mach_init_init(mach_port_t req_port, mach_port_t checkin_port,
		name_array_t l2l_names, mach_port_array_t l2l_ports, pid_t *l2l_pids, mach_msg_type_number_t l2l_cnt)
{
	mach_msg_type_number_t l2l_i;
	auditinfo_t inherited_audit;
	job_t anon_job;

	getaudit(&inherited_audit);
	inherited_asid = inherited_audit.ai_asid;

	launchd_assert((root_job = job_new_bootstrap(NULL, req_port ? req_port : mach_task_self(), checkin_port)) != NULL);

	launchd_assumes(launchd_get_bport(&inherited_bootstrap_port) == KERN_SUCCESS);

	if (getpid() != 1) {
		launchd_assumes(inherited_bootstrap_port != MACH_PORT_NULL);
	}

	/* We set this explicitly as we start each child */
	launchd_assumes(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);

	/* cut off the Libc cache, we don't want to deadlock against ourself */
	bootstrap_port = MACH_PORT_NULL;

	if (l2l_names == NULL) {
		return;
	}

	for (l2l_i = 0; l2l_i < l2l_cnt; l2l_i++) {
		struct machservice *ms;

		if (!(anon_job = job_find_by_pid(root_job, l2l_pids[l2l_i], false))) {
			launchd_assert(anon_job = job_new_anonymous(root_job, l2l_pids[l2l_i]));
		}

		if ((ms = machservice_new(anon_job, l2l_names[l2l_i], &l2l_ports[l2l_i]))) {
			machservice_watch(ms);
		}
	}
}

bool
canReceive(mach_port_t port)
{
	mach_port_type_t p_type;
	
	if (!launchd_assumes(mach_port_type(mach_task_self(), port, &p_type) == KERN_SUCCESS)) {
		return false;
	}

	return ((p_type & MACH_PORT_TYPE_RECEIVE) != 0);
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
job_mig_create_server(job_t j, cmd_t server_cmd, uid_t server_uid, boolean_t on_demand,
		audit_token_t au_tok, mach_port_t *server_portp)
{
	struct ldcred ldc;
	job_t js;

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

	if (js == NULL) {
		return BOOTSTRAP_NO_MEMORY;
	}

	*server_portp = job_get_bsport(js);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_getsocket(job_t j, name_t spr)
{
	if (!sockpath) {
		return BOOTSTRAP_NO_MEMORY;
	} else if (getpid() == 1) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	strncpy(spr, sockpath, sizeof(name_t));
	
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_get_self(job_t j, audit_token_t au_tok, mach_port_t *unprivportp)
{
	struct ldcred ldc;
	job_t j2;

	audit_token_to_launchd_cred(au_tok, &ldc);

	job_log(j, LOG_DEBUG, "Requested unprivileged bootstrap port");

	j2 = job_find_by_pid(j, ldc.pid, false);

	if (!j2) {
		if (ldc.uid == getuid() && ldc.euid == geteuid()) {
			j2 = job_new_anonymous(j, ldc.pid);
			if (!j2) {
				return BOOTSTRAP_NO_MEMORY;
			}
		} else {
			job_log(j, LOG_NOTICE, "PID %u not managed by launchd", ldc.pid);
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
	}

	*unprivportp = job_get_bsport(j2);

	return BOOTSTRAP_SUCCESS;
}

  
kern_return_t
job_mig_check_in(job_t j, name_t servicename, audit_token_t au_tok, mach_port_t *serviceportp)
{
	static pid_t last_warned_pid = 0;
	struct machservice *ms;
	struct ldcred ldc;

	audit_token_to_launchd_cred(au_tok, &ldc);

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
job_mig_register(job_t j, audit_token_t au_tok, name_t servicename, mach_port_t serviceport)
{
	struct machservice *ms;
	struct ldcred ldc;
	job_t j2;

	audit_token_to_launchd_cred(au_tok, &ldc);

	if (j == job_get_bs(j)) {
		j2 = job_find_by_pid(j, ldc.pid, false);
		if (!j2) {
			j2 = job_new_anonymous(j, ldc.pid);
		}
		if (j2) {
			j = j2;
		}
	}

	job_log(j, LOG_NOTICE, "bootstrap_register() is deprecated. PID: %u Service: %s", ldc.pid, servicename);

	job_log(j, LOG_DEBUG, "Mach service registration attempt: %s", servicename);
	
	ms = job_lookup_service(j, servicename, false);

	if (ms) {
		if (machservice_job(ms) != j) {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
		if (machservice_active(ms)) {
			job_log(j, LOG_DEBUG, "Mach service registration failed. Already active: %s", servicename);
			launchd_assumes(!canReceive(machservice_port(ms)));
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		job_checkin(machservice_job(ms));
		machservice_delete(ms);
	}

	if (serviceport != MACH_PORT_NULL) {
		if ((ms = machservice_new(j, servicename, &serviceport))) {
			machservice_watch(ms);
		} else {
			return BOOTSTRAP_NO_MEMORY;
		}
	}

	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_look_up(job_t j, audit_token_t au_tok, name_t servicename, mach_port_t *serviceportp, mach_msg_type_name_t *ptype)
{
	struct machservice *ms;
	struct ldcred ldc;

	audit_token_to_launchd_cred(au_tok, &ldc);

	ms = job_lookup_service(j, servicename, true);

	if (ms && machservice_hidden(ms) && !job_active(machservice_job(ms))) {
		ms = NULL;
	}

	if (ms) {
		launchd_assumes(machservice_port(ms) != MACH_PORT_NULL);
		job_log(j, LOG_DEBUG, "Mach service lookup (by PID %d): %s", ldc.pid, servicename);
		*serviceportp = machservice_port(ms);
		*ptype = MACH_MSG_TYPE_COPY_SEND;
		return BOOTSTRAP_SUCCESS;
	} else if (inherited_bootstrap_port != MACH_PORT_NULL) {
		job_log(j, LOG_DEBUG, "Mach service lookup (by PID %d) forwarded: %s", ldc.pid, servicename);
		*ptype = MACH_MSG_TYPE_MOVE_SEND;
		return bootstrap_look_up(inherited_bootstrap_port, servicename, serviceportp);
	} else {
		job_log(j, LOG_DEBUG, "Mach service lookup (by PID %d) failed: %s", ldc.pid, servicename);
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
}

kern_return_t
job_mig_parent(job_t j, mach_port_t *parentport, mach_msg_type_name_t *pptype)
{
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
job_mig_info_countservices(struct machservice *ms, void *context)
{
	unsigned int *cnt = context;

	(*cnt)++;
}

struct x_bootstrap_info_copyservices_cb {
	name_array_t service_names;
	bootstrap_status_array_t service_actives;
	mach_port_array_t ports;
	pid_t *pids;
	unsigned int i;
};

static void
job_mig_info_copyservices(struct machservice *ms, void *context)
{
	struct x_bootstrap_info_copyservices_cb *info_resp = context;

	strlcpy(info_resp->service_names[info_resp->i], machservice_name(ms), sizeof(info_resp->service_names[0]));

	launchd_assumes(info_resp->service_actives || info_resp->ports);

	if (info_resp->service_actives) {
		info_resp->service_actives[info_resp->i] = machservice_status(ms);
	} else {
		info_resp->ports[info_resp->i] = machservice_port(ms);
		info_resp->pids[info_resp->i] = job_get_pid(machservice_job(ms));
	}
	info_resp->i++;
}

kern_return_t
job_mig_info(job_t j, name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		bootstrap_status_array_t *serviceactivesp, unsigned int *serviceactives_cnt)
{
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, NULL, 0 };
	unsigned int cnt = 0;
	job_t ji;

	for (ji = j; ji; ji = job_parent(ji))
		job_foreach_service(ji, job_mig_info_countservices, &cnt, false);

	mig_allocate((vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	if (!launchd_assumes(info_resp.service_names != NULL)) {
		goto out_bad;
	}

	mig_allocate((vm_address_t *)&info_resp.service_actives, cnt * sizeof(info_resp.service_actives[0]));
	if (!launchd_assumes(info_resp.service_actives != NULL)) {
		goto out_bad;
	}

	for (ji = j; ji; ji = job_parent(ji))
		job_foreach_service(ji, job_mig_info_copyservices, &info_resp, false);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*serviceactivesp = info_resp.service_actives;
	*servicenames_cnt = *serviceactives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names) {
		mig_deallocate((vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	}
	if (info_resp.service_actives) {
		mig_deallocate((vm_address_t)info_resp.service_actives, cnt * sizeof(info_resp.service_actives[0]));
	}

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_transfer_subset(job_t j, mach_port_t *reqport, mach_port_t *rcvright,
		name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		vm_offset_t *service_pids, mach_msg_type_number_t *service_pidsCnt,
		mach_port_array_t *ports, unsigned int *ports_cnt)
{
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, NULL, 0 };
	unsigned int cnt = 0;

	if (getpid() != 1) {
		job_log(j, LOG_ERR, "Only the system launchd will transfer Mach sub-bootstraps.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (!job_parent(j)) {
		job_log(j, LOG_ERR, "Root Mach bootstrap cannot be transferred.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	job_log(j, LOG_DEBUG, "Transferring sub-bootstrap to the per session launchd.");

	job_foreach_service(j, job_mig_info_countservices, &cnt, true);

	mig_allocate((vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	if (!launchd_assumes(info_resp.service_names != NULL)) {
		goto out_bad;
	}

	mig_allocate((vm_address_t *)&info_resp.ports, cnt * sizeof(info_resp.ports[0]));
	if (!launchd_assumes(info_resp.ports != NULL)) {
		goto out_bad;
	}

	mig_allocate((vm_address_t *)&info_resp.pids, cnt * sizeof(pid_t));
	if (!launchd_assumes(info_resp.pids != NULL)) {
		goto out_bad;
	}

	job_foreach_service(j, job_mig_info_copyservices, &info_resp, true);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*ports = info_resp.ports;
	*servicenames_cnt = *ports_cnt = cnt;
	*service_pids = (vm_offset_t)info_resp.pids;
	*service_pidsCnt = cnt * sizeof(pid_t);

	*reqport = job_get_reqport(j);
	*rcvright = job_get_bsport(j);

	launchd_assumes(runtime_remove_mport(*rcvright) == KERN_SUCCESS);

	launchd_assumes(launchd_mport_make_send(*rcvright) == KERN_SUCCESS);

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names) {
		mig_deallocate((vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	}
	if (info_resp.ports) {
		mig_deallocate((vm_address_t)info_resp.ports, cnt * sizeof(info_resp.ports[0]));
	}
	if (info_resp.pids) {
		mig_deallocate((vm_address_t)info_resp.pids, cnt * sizeof(pid_t));
	}

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_subset(job_t j, mach_port_t requestorport, mach_port_t *subsetportp)
{
	int bsdepth = 0;
	job_t js = j;

	while ((js = job_parent(js)) != NULL) {
		bsdepth++;
	}

	/* Since we use recursion, we need an artificial depth for subsets */
	if (bsdepth > 100) {
		job_log(j, LOG_ERR, "Mach sub-bootstrap create request failed. Depth greater than: %d", bsdepth);
		return BOOTSTRAP_NO_MEMORY;
	}

	if ((js = job_new_bootstrap(j, requestorport, MACH_PORT_NULL)) == NULL) {
		if (requestorport == MACH_PORT_NULL) {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
		return BOOTSTRAP_NO_MEMORY;
	}

	*subsetportp = job_get_bsport(js);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_create_service(job_t j, name_t servicename, mach_port_t *serviceportp)
{
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

	*serviceportp = MACH_PORT_NULL;
	ms = machservice_new(j, servicename, serviceportp);

	if (!launchd_assumes(ms != NULL)) {
		goto out_bad;
	}

	return BOOTSTRAP_SUCCESS;

out_bad:
	launchd_assumes(launchd_mport_close_recv(*serviceportp) == KERN_SUCCESS);
	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_wait(job_t j, mach_port_t srp, audit_token_t au_tok, integer_t *waitstatus)
{
#if 0
	struct ldcred ldc;
	audit_token_to_launchd_cred(au_tok, &ldc);
#endif
	return job_handle_mpm_wait(j, srp, waitstatus);
}

kern_return_t
job_mig_uncork_fork(job_t j, audit_token_t au_tok)
{
	if (!j) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	job_uncork_fork(j);

	return 0;
}

kern_return_t
job_mig_spawn(job_t j, audit_token_t au_tok,
		_internal_string_t charbuf, mach_msg_type_number_t charbuf_cnt,
		uint32_t argc, uint32_t envc, uint64_t flags, uint16_t mig_umask,
		pid_t *child_pid, mach_port_t *obsvr_port)
{
	job_t jr;
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

	jr = job_new_spawn(label, path, workingdir, argv, env, flags & SPAWN_HAS_UMASK ? &mig_umask : NULL,
			flags & SPAWN_WANTS_WAIT4DEBUGGER, flags & SPAWN_WANTS_FORCE_PPC);

	if (jr == NULL) switch (errno) {
	case EEXIST:
		return BOOTSTRAP_NAME_IN_USE;
	default:
		return BOOTSTRAP_NO_MEMORY;
	}

	job_log(j, LOG_INFO, "Spawned with flags:%s%s",
			flags & SPAWN_WANTS_FORCE_PPC ? " ppc": "",
			flags & SPAWN_WANTS_WAIT4DEBUGGER ? " stopped": "");

	*child_pid = job_get_pid(jr);
	*obsvr_port = job_get_bsport(jr);

	return BOOTSTRAP_SUCCESS;
}

bool
trusted_client_check(job_t j, struct ldcred *ldc)
{
	static pid_t last_warned_pid = 0;

	/* In the long run, we wish to enforce the progeny rule, but for now,
	 * we'll let root and the user be forgiven. Once we get CoreProcesses
	 * to switch to using launchd rather than the WindowServer for indirect
	 * process invocation, we can then seriously look at cranking up the
	 * warning level here.
	 */

	if (inherited_asid == ldc->asid) {
		return true;
	}
	if (progeny_check(ldc->pid)) {
		return true;
	}
	if (ldc->euid == geteuid()) {
		return true;
	}
	if (ldc->euid == 0 && ldc->uid == 0) {
		return true;
	}
	if (last_warned_pid == ldc->pid) {
		return false;
	}

	job_log(j, LOG_NOTICE, "Security: PID %d (ASID %d) was leaked into this session (ASID %d). This will be denied in the future.", ldc->pid, ldc->asid, inherited_asid);

	last_warned_pid = ldc->pid;

	return false;
}
