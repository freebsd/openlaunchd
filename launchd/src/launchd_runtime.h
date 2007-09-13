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
#ifndef __LAUNCHD_RUNTIME_H__
#define __LAUNCHD_RUNTIME_H__

#include <mach/mach.h>
#include <sys/types.h>
#include <bsm/libbsm.h>
#include <stdbool.h>
#include <syslog.h>

struct ldcred {
	uid_t   euid;
	uid_t   uid;
	gid_t   egid;
	gid_t   gid;
	pid_t   pid;
	au_asid_t asid;
};

/*
 * Use launchd_assumes() when we can recover, even if it means we leak or limp along.
 *
 * Use launchd_assert() for core initialization routines.
 */
#define launchd_assumes(e)	\
	(__builtin_expect(!(e), 0) ? _log_launchd_bug(__rcs_file_version__, __FILE__, __LINE__, #e), false : true)

#define launchd_blame(e, b)	\
	(__builtin_expect(!(e), 0) ? syslog(LOG_DEBUG, "Encountered bug: %d", b), false : true)

#define launchd_assert(e)	if (__builtin_constant_p(e)) { char __compile_time_assert__[e ? 1 : -1] __attribute__((unused)); } else if (!launchd_assumes(e)) { abort(); }

void _log_launchd_bug(const char *rcs_rev, const char *path, unsigned int line, const char *test);

typedef void (*kq_callback)(void *, struct kevent *);
typedef boolean_t (*mig_callback)(mach_msg_header_t *, mach_msg_header_t *);
typedef void (*timeout_callback)(void);

boolean_t launchd_internal_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply);

void runtime_add_ref(void);
void runtime_del_ref(void);

void launchd_runtime_init(void);
void launchd_runtime_init2(void);
void launchd_runtime(void) __attribute__((noreturn));

int runtime_close(int fd);
int runtime_fsync(int fd);

#define RUNTIME_ADVISABLE_IDLE_TIMEOUT 30

void runtime_set_timeout(timeout_callback to_cb, unsigned int sec);
kern_return_t runtime_add_mport(mach_port_t name, mig_callback demux, mach_msg_size_t msg_size);
kern_return_t runtime_remove_mport(mach_port_t name);
bool runtime_get_caller_creds(struct ldcred *ldc);

const char *signal_to_C_name(unsigned int sig);
const char *reboot_flags_to_C_names(unsigned int flags);


int kevent_bulk_mod(struct kevent *kev, size_t kev_cnt);
int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);

pid_t runtime_fork(mach_port_t bsport);

kern_return_t runtime_log_forward(uid_t forward_uid, gid_t forward_gid, vm_offset_t inval, mach_msg_type_number_t invalCnt);
kern_return_t runtime_log_drain(mach_port_t srp, vm_offset_t *outval, mach_msg_type_number_t *outvalCnt);

#define LOG_APPLEONLY 0x4141504c /* AAPL in hex */

struct runtime_syslog_attr {
	const char *from_name;
	const char *about_name;
	const char *session_name;
	int priority;
	uid_t from_uid;
	pid_t from_pid;
	pid_t about_pid;
};

int runtime_setlogmask(int maskpri);
void runtime_closelog(void);
void runtime_syslog(int pri, const char *message, ...) __attribute__((format(printf, 2, 3)));
void runtime_vsyslog(struct runtime_syslog_attr *attr, const char *message, va_list args) __attribute__((format(printf, 2, 0)));


kern_return_t launchd_set_bport(mach_port_t name);
kern_return_t launchd_get_bport(mach_port_t *name);
kern_return_t launchd_mport_notify_req(mach_port_t name, mach_msg_id_t which);
kern_return_t launchd_mport_notify_cancel(mach_port_t name, mach_msg_id_t which);
kern_return_t launchd_mport_create_recv(mach_port_t *name);
kern_return_t launchd_mport_deallocate(mach_port_t name);
kern_return_t launchd_mport_make_send(mach_port_t name);
kern_return_t launchd_mport_close_recv(mach_port_t name);

#endif
