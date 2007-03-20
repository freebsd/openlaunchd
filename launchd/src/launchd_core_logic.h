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

#include "libbootstrap_public.h"
#include "liblaunch_public.h"

typedef struct job_s *job_t;
typedef struct jobmgr_s *jobmgr_t;

extern jobmgr_t root_jobmgr;

void jobmgr_init(bool);
jobmgr_t jobmgr_shutdown(jobmgr_t jm);
void jobmgr_dispatch_all_semaphores(jobmgr_t jm);
job_t jobmgr_get_anonymous(jobmgr_t jm);
job_t jobmgr_find(jobmgr_t jm, const char *label);
jobmgr_t jobmgr_delete_anything_with_port(jobmgr_t jm, mach_port_t port);
bool jobmgr_ack_port_destruction(jobmgr_t jm, mach_port_t p);
job_t jobmgr_find_by_service_port(jobmgr_t jm, mach_port_t p);

launch_data_t job_export_all(void);

job_t job_dispatch(job_t j, bool kickstart); /* returns j on success, NULL on job removal */
bool job_active(job_t j);
bool job_is_anonymous(job_t j);
launch_data_t job_export(job_t j);
void job_stop(job_t j);
void job_checkin(job_t j);
void job_remove(job_t j);
job_t job_import(launch_data_t pload);
launch_data_t job_import_bulk(launch_data_t pload);
job_t job_mig_intran(mach_port_t mp);
void job_mig_destructor(job_t j);
void job_ack_no_senders(job_t j);
void job_log(job_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));

#endif
