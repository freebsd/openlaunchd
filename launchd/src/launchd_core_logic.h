#ifndef __LAUNCHD_CORE_LOGIC__
#define __LAUNCHD_CORE_LOGIC__
/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

#define LAUNCHD_MIN_JOB_RUN_TIME 10
#define LAUNCHD_REWARD_JOB_RUN_TIME 60
#define LAUNCHD_FAILED_EXITS_THRESHOLD 10

struct jobcb;
struct bootstrap;
struct machservice;

#define ANY_JOB ((struct jobcb *)-1)

struct bootstrap *bootstrap_new(struct bootstrap *parent, mach_port_name_t requestorport);
void bootstrap_delete(struct bootstrap *bootstrap);
void bootstrap_delete_anything_with_port(struct bootstrap *bootstrap, mach_port_t port);
mach_port_t bootstrap_rport(struct bootstrap *bootstrap);
struct bootstrap *bootstrap_rparent(struct bootstrap *bootstrap);
struct machservice *bootstrap_lookup_service(struct bootstrap *bootstrap, const char *name, bool check_parent);
void bootstrap_callback(void *obj, struct kevent *kev);
void bootstrap_foreach_service(struct bootstrap *bootstrap, void (*bs_iter)(struct machservice *, void *), void *context);


struct machservice *machservice_new(struct bootstrap *bootstrap, const char *name, mach_port_t *serviceport, struct jobcb *j);
void machservice_delete(struct machservice *servicep);
void machservice_watch(struct machservice *servicep);
mach_port_t machservice_port(struct machservice *servicep);
struct jobcb *machservice_job(struct machservice *servicep);
bool machservice_active(struct machservice *servicep);
const char *machservice_name(struct machservice *servicep);
struct bootstrap *machservice_bootstrap(struct machservice *servicep);


struct jobcb *job_find(const char *label);
struct jobcb *job_import(launch_data_t pload);
launch_data_t job_import_bulk(launch_data_t pload);
struct jobcb *job_new(struct bootstrap *b, const char *label, const char *prog, const char *const *argv, const char *stdinpath);
struct jobcb *job_new_via_mach_init(struct bootstrap *bootstrap, const char *cmd, uid_t uid, bool ond);
launch_data_t job_export(struct jobcb *j);
launch_data_t job_export_all(void);
void job_dispatch(struct jobcb *j);
void job_dispatch_all_other_semaphores(struct jobcb *j, struct bootstrap *b);
void job_start(struct jobcb *j);
void job_stop(struct jobcb *j);
bool job_active(struct jobcb *j);
void job_checkin(struct jobcb *j);
bool job_ondemand(struct jobcb *j);
const char *job_prog(struct jobcb *j);
#ifdef PID1_REAP_ADOPTED_CHILDREN
bool job_reap_pid(pid_t p);
#endif
void job_remove(struct jobcb *j);
void job_remove_all_inactive(void);
void job_ack_port_destruction(struct jobcb *j, mach_port_t p);
void job_ack_no_senders(struct jobcb *j);
mach_port_t job_get_priv_port(struct jobcb *j);

extern size_t total_children;

extern struct bootstrap *root_bootstrap;
extern struct bootstrap *ws_bootstrap;
extern struct bootstrap *current_rpc_bootstrap;
extern struct jobcb *current_rpc_server;

#endif
