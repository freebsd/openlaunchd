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
#ifndef _LAUNCH_PRIV_H_
#define _LAUNCH_PRIV_H_

#include <launch.h>

__BEGIN_DECLS

#define LAUNCH_KEY_GETUSERENVIRONMENT	"GetUserEnvironment"
#define LAUNCH_KEY_SETUSERENVIRONMENT	"SetUserEnvironment"
#define LAUNCH_KEY_UNSETUSERENVIRONMENT	"UnsetUserEnvironment"
#define LAUNCH_KEY_SETSTDOUT		"SetStandardOut"
#define LAUNCH_KEY_SETSTDERR		"SetStandardError"
#define LAUNCH_KEY_SHUTDOWN		"Shutdown"
#define LAUNCH_KEY_SINGLEUSER		"SingleUser"
#define LAUNCH_KEY_GETRESOURCELIMITS	"GetResourceLimits"
#define LAUNCH_KEY_SETRESOURCELIMITS	"SetResourceLimits"
#define LAUNCH_KEY_RELOADTTYS		"ReloadTTYS"
#define LAUNCH_KEY_SETLOGMASK		"SetLogMask"
#define LAUNCH_KEY_GETLOGMASK		"GetLogMask"
#define LAUNCH_KEY_SETUMASK		"SetUmask"
#define LAUNCH_KEY_GETUMASK		"GetUmask"
#define LAUNCH_KEY_GETRUSAGESELF	"GetResourceUsageSelf"
#define LAUNCH_KEY_GETRUSAGECHILDREN	"GetResourceUsageChildren"

#define LAUNCHD_SOCKET_ENV		"LAUNCHD_SOCKET"
#define LAUNCHD_SOCK_PREFIX		"/var/tmp/launchd"
#define LAUNCHD_TRUSTED_FD_ENV		"__LAUNCHD_FD"
#define LAUNCHD_ASYNC_MSG_KEY		"_AsyncMessage"
#define LAUNCH_KEY_BATCHCONTROL		"BatchControl"
#define LAUNCH_KEY_BATCHQUERY		"BatchQuery"

#define LAUNCH_JOBKEY_MACH_KUNCSERVER	"kUNCServer"

typedef struct _launch *launch_t;

launch_t launchd_fdopen(int);
int launchd_getfd(launch_t);
void launchd_close(launch_t);

launch_data_t   launch_data_new_errno(int);
bool		launch_data_set_errno(launch_data_t, int);

int launchd_msg_send(launch_t, launch_data_t);
int launchd_msg_recv(launch_t, void (*)(launch_data_t, void *), void *);

/* For LoginWindow.
 *
 * After this call, the task's bootstrap port is set to the per session launchd.
 *
 * This returns the PID on of the per session launchd, and -1 on failure.
 * 
 * If launchd terminates, loginwindow should exit.
 * If loginwindow terminates, launchd will exit.
 */
#define	LOAD_ONLY_SAFEMODE_LAUNCHAGENTS	1
pid_t create_and_switch_to_per_session_launchd(const char *login, int flags, ...);

/* batch jobs will be implicity re-enabled when the last application who
 * disabled them exits.
 *
 * This API is really a hack to work around the lack of real-time APIs
 * at the VFS layer.
 */
void launchd_batch_enable(bool);
bool launchd_batch_query(void);

/* For CoreProcesses
 */

#define SPAWN_VIA_LAUNCHD_STOPPED	0x0001

struct spawn_via_launchd_attr {
	uint64_t		spawn_flags;
	const char *		spawn_path;
	const char *		spawn_chdir;
 	const char *const *	spawn_env;
 	const mode_t *		spawn_umask;
};

#define spawn_via_launchd(a, b, c) _spawn_via_launchd(a, b, c, 0)
pid_t _spawn_via_launchd(
		const char *label,
		const char *const *argv,
		const struct spawn_via_launchd_attr *spawn_attrs,
		int struct_version);

__END_DECLS

#endif
