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
#ifndef _LAUNCH_PRIV_H_
#define _LAUNCH_PRIV_H_

#include <mach/mach.h>
#include <sys/types.h>
#include <launch.h>
#include <unistd.h>
#include <quarantine.h>

#pragma GCC visibility push(default)

__BEGIN_DECLS

#define LAUNCH_KEY_SETUSERENVIRONMENT	"SetUserEnvironment"
#define LAUNCH_KEY_UNSETUSERENVIRONMENT	"UnsetUserEnvironment"
#define LAUNCH_KEY_SHUTDOWN		"Shutdown"
#define LAUNCH_KEY_SINGLEUSER		"SingleUser"
#define LAUNCH_KEY_GETRESOURCELIMITS	"GetResourceLimits"
#define LAUNCH_KEY_SETRESOURCELIMITS	"SetResourceLimits"
#define LAUNCH_KEY_GETRUSAGESELF	"GetResourceUsageSelf"
#define LAUNCH_KEY_GETRUSAGECHILDREN	"GetResourceUsageChildren"

#define LAUNCHD_SOCKET_ENV		"LAUNCHD_SOCKET"
#define LAUNCHD_SOCK_PREFIX		"/var/tmp/launchd"
#define LAUNCHD_TRUSTED_FD_ENV		"__LAUNCHD_FD"
#define LAUNCHD_ASYNC_MSG_KEY		"_AsyncMessage"
#define LAUNCH_KEY_BATCHCONTROL		"BatchControl"
#define LAUNCH_KEY_BATCHQUERY		"BatchQuery"

#define LAUNCH_JOBKEY_QUARANTINEDATA	"QuarantineData"
#define LAUNCH_JOBKEY_SANDBOXPROFILE	"SandboxProfile"
#define LAUNCH_JOBKEY_SANDBOXFLAGS	"SandboxFlags"
#define LAUNCH_JOBKEY_SANDBOX_NAMED	"Named"

#define LAUNCH_JOBKEY_ENTERKERNELDEBUGGERBEFOREKILL	"EnterKernelDebuggerBeforeKill"
#define LAUNCH_JOBKEY_PERJOBMACHSERVICES	"PerJobMachServices"
#define LAUNCH_JOBKEY_SERVICEIPC		"ServiceIPC"
#define LAUNCH_JOBKEY_BINARYORDERPREFERENCE	"BinaryOrderPreference"
#define LAUNCH_JOBKEY_MACHEXCEPTIONHANDLER	"MachExceptionHandler"

#define LAUNCH_JOBKEY_MACH_KUNCSERVER	"kUNCServer"
#define LAUNCH_JOBKEY_MACH_EXCEPTIONSERVER	"ExceptionServer"
#define LAUNCH_JOBKEY_MACH_TASKSPECIALPORT	"TaskSpecialPort"
#define LAUNCH_JOBKEY_MACH_HOSTSPECIALPORT	"HostSpecialPort"
#define LAUNCH_JOBKEY_MACH_ENTERKERNELDEBUGGERONCLOSE	"EnterKernelDebuggerOnClose"

typedef struct _launch *launch_t;

launch_t launchd_fdopen(int);
int launchd_getfd(launch_t);
void launchd_close(launch_t, typeof(close) closefunc);

launch_data_t   launch_data_new_errno(int);
bool		launch_data_set_errno(launch_data_t, int);

int launchd_msg_send(launch_t, launch_data_t);
int launchd_msg_recv(launch_t, void (*)(launch_data_t, void *), void *);

/* For LoginWindow.
 *
 * After this call, the task's bootstrap port is set to the per session launchd.
 *
 * This returns 1 on success (it used to return otherwise), and -1 on failure.
 */
#define	LOAD_ONLY_SAFEMODE_LAUNCHAGENTS	1
pid_t create_and_switch_to_per_session_launchd(const char * /* loginname */, int flags, ...);

/* Also for LoginWindow.
 *
 * This is will load jobs at the LoginWindow prompt.
 */
void load_launchd_jobs_at_loginwindow_prompt(int flags, ...);


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
 	mach_port_t *		spawn_observer_port;
 	const cpu_type_t *	spawn_binpref;
	size_t			spawn_binpref_cnt;
	qtn_proc_t		spawn_quarantine;
	const char *		spawn_seatbelt_profile;
	const uint64_t *	spawn_seatbelt_flags;
};

#define spawn_via_launchd(a, b, c) _spawn_via_launchd(a, b, c, 2)
pid_t _spawn_via_launchd(
		const char *label,
		const char *const *argv,
		const struct spawn_via_launchd_attr *spawn_attrs,
		int struct_version);

kern_return_t mpm_wait(mach_port_t ajob, int *wstatus);

kern_return_t mpm_uncork_fork(mach_port_t ajob);


__END_DECLS

#pragma GCC visibility pop


#endif
