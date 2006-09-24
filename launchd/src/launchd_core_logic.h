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
#include "launch.h"

typedef struct job_s *job_t;

extern job_t root_job;
extern job_t gc_this_job;
extern size_t total_children;

job_t job_new(job_t p, const char *label, const char *prog, const char *const *argv, const char *stdinpath, mach_port_t);
void job_dispatch(job_t j, bool kickstart);
bool job_active(job_t j);
void job_remove_all_inactive(job_t j);
void job_dispatch_all_other_semaphores(job_t j, job_t nj);
launch_data_t job_export(job_t j);
launch_data_t job_export_all(void);
void job_stop(job_t j);
void job_checkin(job_t j);
void job_remove(job_t j);
job_t job_find(job_t j, const char *label);
job_t job_import(launch_data_t pload);
launch_data_t job_import_bulk(launch_data_t pload);
job_t job_mig_intran(mach_port_t mp);
void job_mig_destructor(job_t j);
bool job_ack_port_destruction(job_t j, mach_port_t p);
void job_ack_no_senders(job_t j);
void job_delete_anything_with_port(job_t jbs, mach_port_t port);

#endif
