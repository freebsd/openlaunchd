#ifndef _VPROC_H_
#define _VPROC_H_
/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/cdefs.h>

__BEGIN_DECLS

#if 0

typedef void * vproc_t;
typedef void * vprocmgr_t;
typedef void * vproc_err_t;

/* By default, pass NULL for vprocmgr_t or vproc_t to get notions of self or "my manager" */

vproc_err_t vprocmgr_create_vproc(vprocmgr_t vpm, launch_data_t the_vproc, vproc_t *vp);

/* If creating multiple jobs, it is wise to create them atomically with respect to each other */
vproc_err_t vprocmgr_create_vprocs(vprocmgr_t vpm, launch_data_t *the_vprocs, vproc_t *vp, size_t cnt);

vproc_err_t vprocmgr_delete_vproc(vprocmgr_t vpm, vproc_t vp);

/* The virtual process managers are arranged in a hierarchy */
vproc_err_t vprocmgr_get_parent(vprocmgr_t vpm, vprocmgr_t *vpm_parent);

vproc_err_t vprocmgr_get_all_vprocs(vprocmgr_t vpm, vproc_t **vps, size_t *vp_cnt);

vproc_err_t vprocmgr_lookup_vproc(vprocmgr_t vpm, const char *label, vproc_t *vp);

vproc_err_t vprocmgr_lookup_vprocmgr_for_user(vprocmgr_t vpm, const char *user, vprocmgr_t *vpm_out);

vproc_err_t vprocmgr_lookup_mach_service(vprocmgr_t vpm, const char *service, mach_port_t *service_port);

/* For controlling speculative and optimistical spawning of vprocs */
vproc_err_t vprocmgr_set_force_on_demand(vproc_mgr_t vpm, bool force);
vproc_err_t vprocmgr_get_force_on_demand(vproc_mgr_t vpm, bool *force);

/* Only release those vprocmgr_t objects that returned from APIs. */
vproc_err_t vprocmgr_release(vprocmgr_t vpm);


/* Get meta-data and IPC handles from launchd */
vproc_err_t vproc_checkin(launch_data_t *out);

/* Get only meta-data from launchd */
vproc_err_t vproc_get_info(vproc_t vp, launch_data_t *out);

/* Lookup a Mach service amongst our peers and progenitors */
vproc_err_t vproc_lookup_mach_service(vproc_t vp, const char *service, mach_port_t *service_port);

/* Sending signals to a program that isn't running will return an error */
vproc_err_t vproc_send_signal(vproc_t vp, int signum);

/* Only release those vproc_t objects that returned from APIs. */
vproc_err_t vproc_release(vproc_t vp);



const char *vproc_strerror(vproc_err_t r);

#endif

__END_DECLS

#endif
