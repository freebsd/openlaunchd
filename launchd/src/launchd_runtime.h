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
#include <stdint.h>
#include <float.h>
#include <syslog.h>

#include "launchd_runtime_kill.h"
#include "launchd_ktrace.h"

#if 0

/* I need to do more testing of these macros */

#define min_of_type(x) \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), long double), LDBL_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), double), DBL_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), float), FLT_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), char), 0, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), signed char), INT8_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), short), INT16_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), int), INT32_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), long), (__builtin_choose_expr(sizeof(x) == 4, INT32_MIN, INT64_MIN)), \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), long long), INT64_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned char), 0, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned short), 0, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned int), 0, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned long), 0, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned long long), 0, \
	(void)0))))))))))))))

#define max_of_type(x) \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), long double), LDBL_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), double), DBL_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), float), FLT_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), char), UINT8_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), signed char), INT8_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), short), INT16_MIN, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), int), INT32_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), long), (__builtin_choose_expr(sizeof(x) == 4, INT32_MAX, INT64_MAX)), \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), long long), INT64_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned char), UINT8_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned short), UINT16_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned int), UINT32_MAX, \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned long), (__builtin_choose_expr(sizeof(x) == 4, UINT32_MAX, UINT64_MAX)), \
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(x), unsigned long long), UINT64_MAX, \
	(void)0))))))))))))))

#endif

#ifdef __i386__
#define INTERNAL_ABI __attribute__((regparm(3)))
#else
#define INTERNAL_ABI
#endif

#define	likely(x)	__builtin_expect((bool)(x), true)
#define	unlikely(x)	__builtin_expect((bool)(x), false)

struct ldcred {
	uid_t   euid;
	uid_t   uid;
	gid_t   egid;
	gid_t   gid;
	pid_t   pid;
};

/*
 * Use launchd_assumes() when we can recover, even if it means we leak or limp along.
 *
 * Use launchd_assert() for core initialization routines.
 */
#define launchd_assumes(e)	\
	(unlikely(!(e)) ? _log_launchd_bug(__rcs_file_version__, __FILE__, __LINE__, #e), false : true)

#define launchd_assert(e)	if (__builtin_constant_p(e)) { char __compile_time_assert__[e ? 1 : -1] __attribute__((unused)); } else if (!launchd_assumes(e)) { abort(); }

INTERNAL_ABI void _log_launchd_bug(const char *rcs_rev, const char *path, unsigned int line, const char *test);

typedef INTERNAL_ABI void (*kq_callback)(void *, struct kevent *);
typedef boolean_t (*mig_callback)(mach_msg_header_t *, mach_msg_header_t *);
typedef INTERNAL_ABI void (*timeout_callback)(void);

extern bool pid1_magic;
extern bool low_level_debug;
extern char g_username[128];

INTERNAL_ABI mach_port_t runtime_get_kernel_port(void);

INTERNAL_ABI void runtime_add_ref(void);
INTERNAL_ABI void runtime_del_ref(void);
INTERNAL_ABI void runtime_add_weak_ref(void);
INTERNAL_ABI void runtime_del_weak_ref(void);

INTERNAL_ABI void launchd_runtime_init(void);
INTERNAL_ABI void launchd_runtime_init2(void);
INTERNAL_ABI void launchd_runtime(void) __attribute__((noreturn));

INTERNAL_ABI void launchd_log_vm_stats(void);

INTERNAL_ABI int runtime_close(int fd);
INTERNAL_ABI int runtime_fsync(int fd);

#define RUNTIME_ADVISABLE_IDLE_TIMEOUT 30

INTERNAL_ABI void runtime_set_timeout(timeout_callback to_cb, unsigned int sec);
INTERNAL_ABI kern_return_t runtime_add_mport(mach_port_t name, mig_callback demux, mach_msg_size_t msg_size);
INTERNAL_ABI kern_return_t runtime_remove_mport(mach_port_t name);
INTERNAL_ABI struct ldcred *runtime_get_caller_creds(void);

INTERNAL_ABI const char *signal_to_C_name(unsigned int sig);
INTERNAL_ABI const char *reboot_flags_to_C_names(unsigned int flags);
INTERNAL_ABI const char *proc_flags_to_C_names(unsigned int flags);

INTERNAL_ABI int kevent_bulk_mod(struct kevent *kev, size_t kev_cnt);
INTERNAL_ABI int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);

INTERNAL_ABI pid_t runtime_fork(mach_port_t bsport);

INTERNAL_ABI kern_return_t runtime_log_forward(uid_t forward_uid, gid_t forward_gid, vm_offset_t inval, mach_msg_type_number_t invalCnt);
INTERNAL_ABI kern_return_t runtime_log_drain(mach_port_t srp, vm_offset_t *outval, mach_msg_type_number_t *outvalCnt);

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

INTERNAL_ABI int runtime_setlogmask(int maskpri);
INTERNAL_ABI void runtime_closelog(void);
INTERNAL_ABI void runtime_syslog(int pri, const char *message, ...) __attribute__((format(printf, 2, 3)));
INTERNAL_ABI void runtime_vsyslog(struct runtime_syslog_attr *attr, const char *message, va_list args) __attribute__((format(printf, 2, 0)));
INTERNAL_ABI void runtime_log_push(void);

INTERNAL_ABI int64_t runtime_get_wall_time(void) __attribute__((warn_unused_result));
INTERNAL_ABI uint64_t runtime_get_opaque_time(void) __attribute__((warn_unused_result));
INTERNAL_ABI uint64_t runtime_get_opaque_time_of_event(void) __attribute__((pure, warn_unused_result));
INTERNAL_ABI uint64_t runtime_opaque_time_to_nano(uint64_t o) __attribute__((const, warn_unused_result));
INTERNAL_ABI uint64_t runtime_get_nanoseconds_since(uint64_t o) __attribute__((pure, warn_unused_result));

INTERNAL_ABI kern_return_t launchd_set_bport(mach_port_t name);
INTERNAL_ABI kern_return_t launchd_get_bport(mach_port_t *name);
INTERNAL_ABI kern_return_t launchd_mport_notify_req(mach_port_t name, mach_msg_id_t which);
INTERNAL_ABI kern_return_t launchd_mport_notify_cancel(mach_port_t name, mach_msg_id_t which);
INTERNAL_ABI kern_return_t launchd_mport_create_recv(mach_port_t *name);
INTERNAL_ABI kern_return_t launchd_mport_deallocate(mach_port_t name);
INTERNAL_ABI kern_return_t launchd_mport_make_send(mach_port_t name);
INTERNAL_ABI kern_return_t launchd_mport_close_recv(mach_port_t name);

#endif
