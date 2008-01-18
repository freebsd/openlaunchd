#ifndef _VPROC_PRIVATE_H_
#define _VPROC_PRIVATE_H_
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

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <stdbool.h>
#include <launch.h>

__BEGIN_DECLS

#pragma GCC visibility push(default)

/* DO NOT use this. This is a hack for launchctl */
#define VPROC_MAGIC_UNLOAD_SIGNAL 0x4141504C

typedef enum {
	VPROC_GSK_LAST_EXIT_STATUS = 1,
	VPROC_GSK_GLOBAL_ON_DEMAND,
	VPROC_GSK_MGR_UID,
	VPROC_GSK_MGR_PID,
	VPROC_GSK_IS_MANAGED,
	VPROC_GSK_BASIC_KEEPALIVE,
	VPROC_GSK_START_INTERVAL,
	VPROC_GSK_IDLE_TIMEOUT,
	VPROC_GSK_EXIT_TIMEOUT,
	VPROC_GSK_ENVIRONMENT,
	VPROC_GSK_ALLJOBS,
	VPROC_GSK_GLOBAL_LOG_MASK,
	VPROC_GSK_GLOBAL_UMASK,
} vproc_gsk_t;

vproc_err_t vproc_swap_integer(vproc_t vp, vproc_gsk_t key, int64_t *inval, int64_t *outval);
vproc_err_t vproc_swap_complex(vproc_t vp, vproc_gsk_t key, launch_data_t inval, launch_data_t *outval);

vproc_err_t _vproc_get_last_exit_status(int *wstatus);
vproc_err_t _vproc_set_global_on_demand(bool val);

typedef void (*_vprocmgr_log_drain_callback_t)(struct timeval *when, pid_t from_pid, pid_t about_pid, uid_t sender_uid, gid_t sender_gid, int priority, const char *from_name, const char *about_name, const char *session_name, const char *msg);

vproc_err_t _vprocmgr_log_drain(vproc_t vp, pthread_mutex_t *optional_mutex_around_callback, _vprocmgr_log_drain_callback_t func);

vproc_err_t _vproc_send_signal_by_label(const char *label, int sig);
vproc_err_t _vproc_kickstart_by_label(const char *label, pid_t *out_pid, mach_port_t *out_port_name);
vproc_err_t _vproc_wait_by_label(const char *label, int *out_wstatus);

void _vproc_log(int pri, const char *msg, ...) __attribute__((format(printf, 2, 3)));
void _vproc_log_error(int pri, const char *msg, ...) __attribute__((format(printf, 2, 3)));

#define VPROCMGR_SESSION_LOGINWINDOW	"LoginWindow"
#define VPROCMGR_SESSION_BACKGROUND	"Background"
#define VPROCMGR_SESSION_AQUA		"Aqua"
#define VPROCMGR_SESSION_STANDARDIO	"StandardIO"
#define VPROCMGR_SESSION_SYSTEM		"System"

vproc_err_t _vprocmgr_move_subset_to_user(uid_t target_user, const char *session_type);

#pragma GCC visibility pop

__END_DECLS

#endif
