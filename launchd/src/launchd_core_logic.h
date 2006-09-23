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

#include "bootstrap_public.h"

#define job_assumes(j, e)      \
	        (__builtin_expect(!(e), 0) ? job_log_bug(j, __rcs_file_version__, __FILE__, __LINE__, #e), false : true)


typedef struct job_s *job_t;
struct machservice;


struct machservice *machservice_new(job_t j, const char *name, mach_port_t *serviceport);
void machservice_delete(struct machservice *);
void machservice_watch(struct machservice *);
mach_port_t machservice_port(struct machservice *);
job_t machservice_job(struct machservice *);
bool machservice_hidden(struct machservice *);
bool machservice_active(struct machservice *);
const char *machservice_name(struct machservice *);
bootstrap_status_t machservice_status(struct machservice *);


job_t job_find(job_t j, const char *label);
job_t job_find_by_pid(job_t j, pid_t p, bool recurse);
job_t job_find_by_port(mach_port_t mp);
job_t job_import(launch_data_t pload);
launch_data_t job_import_bulk(launch_data_t pload);
job_t job_new(job_t p, const char *label, const char *prog, const char *const *argv, const char *stdinpath, mach_port_t);
job_t job_new_spawn(const char *label, const char *path, const char *workingdir, const char *const *argv, const char *const *env, mode_t *u_mask, bool w4d, bool fppc);
job_t job_new_via_mach_init(job_t jbs, const char *cmd, uid_t uid, bool ond);
job_t job_new_bootstrap(job_t p, mach_port_t requestorport, mach_port_t checkin_port);
launch_data_t job_export(job_t j);
launch_data_t job_export_all(void);
void job_dispatch(job_t j, bool kickstart);
void job_dispatch_all_other_semaphores(job_t j, job_t nj);
void job_stop(job_t j);
bool job_active(job_t j);
void job_checkin(job_t j);
const char *job_prog(job_t j);
void job_remove(job_t j);
void job_remove_all_inactive(job_t j);
bool job_ack_port_destruction(job_t j, mach_port_t p);
void job_ack_no_senders(job_t j);
pid_t job_get_pid(job_t j);
mach_port_t job_get_bsport(job_t j);
mach_port_t job_get_reqport(job_t j);
job_t job_get_bs(job_t j);
void job_delete_anything_with_port(job_t jbs, mach_port_t port);
job_t job_parent(job_t j);
void job_uncork_fork(job_t j);
struct machservice *job_lookup_service(job_t jbs, const char *name, bool check_parent);
void job_foreach_service(job_t jbs, void (*bs_iter)(struct machservice *, void *), void *context, bool include_subjobs);
void job_log(job_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
void job_log_error(job_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
void job_log_bug(job_t j, const char *rcs_rev, const char *path, unsigned int line, const char *test);
kern_return_t job_handle_mpm_wait(job_t j, mach_port_t srp, int *waitstatus);

extern size_t total_children;

extern job_t root_job;

extern job_t gc_this_job;

#endif
