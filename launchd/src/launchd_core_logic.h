#ifndef __LAUNCHD_CORE_LOGIC__
#define __LAUNCHD_CORE_LOGIC__
/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

#define LAUNCHD_MIN_JOB_RUN_TIME 10

#include "bootstrap_public.h"

#define job_assumes(j, e)      \
	        (__builtin_expect(!(e), 0) ? job_log_bug(j, __rcs_file_version__, __FILE__, __LINE__, #e), false : true)


typedef struct vproc_s *vproc_t;
struct machservice;


struct machservice *machservice_new(vproc_t j, const char *name, mach_port_t *serviceport);
void machservice_delete(struct machservice *);
void machservice_watch(struct machservice *);
mach_port_t machservice_port(struct machservice *);
vproc_t machservice_job(struct machservice *);
bool machservice_hidden(struct machservice *);
bool machservice_active(struct machservice *);
const char *machservice_name(struct machservice *);
bootstrap_status_t machservice_status(struct machservice *);


vproc_t job_find(vproc_t j, const char *label);
vproc_t job_find_by_pid(vproc_t j, pid_t p);
vproc_t job_find_by_port(mach_port_t mp);
vproc_t job_import(launch_data_t pload);
launch_data_t job_import_bulk(launch_data_t pload);
vproc_t job_new(vproc_t p, const char *label, const char *prog, const char *const *argv, const char *stdinpath, mach_port_t);
vproc_t job_new_spawn(const char *label, const char *path, const char *workingdir, const char *const *argv, const char *const *env, mode_t *u_mask, bool w4d, bool fppc);
vproc_t job_new_via_mach_init(vproc_t jbs, const char *cmd, uid_t uid, bool ond);
vproc_t job_new_bootstrap(vproc_t p, mach_port_t requestorport, mach_port_t checkin_port);
launch_data_t job_export(vproc_t j);
launch_data_t job_export_all(void);
void job_dispatch(vproc_t j, bool kickstart);
void job_dispatch_all_other_semaphores(vproc_t j, vproc_t nj);
void job_stop(vproc_t j);
bool job_active(vproc_t j);
void job_checkin(vproc_t j);
const char *job_prog(vproc_t j);
void job_remove(vproc_t j);
void job_remove_all_inactive(vproc_t j);
bool job_ack_port_destruction(vproc_t j, mach_port_t p);
void job_ack_no_senders(vproc_t j);
pid_t job_get_pid(vproc_t j);
mach_port_t job_get_bsport(vproc_t j);
mach_port_t job_get_reqport(vproc_t j);
vproc_t job_get_bs(vproc_t j);
void job_delete_anything_with_port(vproc_t jbs, mach_port_t port);
vproc_t job_parent(vproc_t j);
void job_uncork_fork(vproc_t j);
struct machservice *job_lookup_service(vproc_t jbs, const char *name, bool check_parent);
void job_foreach_service(vproc_t jbs, void (*bs_iter)(struct machservice *, void *), void *context, bool include_subjobs);
void job_log(vproc_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
void job_log_error(vproc_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
void job_log_bug(vproc_t j, const char *rcs_rev, const char *path, unsigned int line, const char *test);
kern_return_t job_handle_mpm_wait(vproc_t j, mach_port_t srp, int *waitstatus);

extern size_t total_children;

extern vproc_t root_job;

extern vproc_t gc_this_job;

#endif
