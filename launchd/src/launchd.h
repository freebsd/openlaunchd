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
#ifndef __LAUNCHD_H__
#define __LAUNCHD_H__

#include <mach/mach.h>
#include <mach/port.h>
#include "launch.h"
#include "bootstrap_public.h"

/*
 * Use launchd_assumes() when we can recover, even if it means we leak or limp along.
 *
 * Use launchd_assert() for core initialization routines.
 */
#define launchd_assumes(e)	\
	(__builtin_expect(!(e), 0) ? _log_launchd_bug(__rcs_file_version__, __FILE__, __LINE__, #e), false : true)

#define launchd_blame(e, b)	\
	(__builtin_expect(!(e), 0) ? syslog(LOG_DEBUG, "Encountered bug: %d", b), false : true)

#define launchd_assert(e)	launchd_assumes(e) ? true : abort();

#define FIRSTBORN_LABEL "com.apple.launchd.firstborn"
#define READCONF_LABEL "com.apple.launchd.readconfig"

struct kevent;
struct conncb;

typedef void (*kq_callback)(void *, struct kevent *);

extern kq_callback kqsimple_zombie_reaper;
extern sigset_t blocked_signals;
extern bool shutdown_in_progress;
extern bool network_up;
extern int batch_disabler_count;
extern mach_port_t launchd_internal_port;
extern mach_port_t ipc_port_set;

bool init_check_pid(pid_t);

int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);
void batch_job_enable(bool e, struct conncb *c);

launch_data_t launchd_setstdio(int d, launch_data_t o);
void launchd_SessionCreate(void);
void launchd_shutdown(void);
void launchd_single_user(void);
pid_t launchd_fork(void);
boolean_t launchd_mach_ipc_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply);

kern_return_t launchd_set_bport(mach_port_t name);
kern_return_t launchd_get_bport(mach_port_t *name);
kern_return_t launchd_mport_notify_req(mach_port_t name, mach_msg_id_t which);
kern_return_t launchd_mport_notify_cancel(mach_port_t name, mach_msg_id_t which);
kern_return_t launchd_mport_request_callback(mach_port_t name, void *obj, bool readmsg);
kern_return_t launchd_mport_create_recv(mach_port_t *name);
kern_return_t launchd_mport_deallocate(mach_port_t name);
kern_return_t launchd_mport_make_send(mach_port_t name);
kern_return_t launchd_mport_close_recv(mach_port_t name);

void init_boot(bool sflag);
void init_pre_kevent(void);

void update_ttys(void);
void catatonia(void);

void mach_start_shutdown(void);
void mach_init_init(mach_port_t, mach_port_t, name_array_t, mach_port_array_t, mach_msg_type_number_t);
void mach_init_reap(void);

int _fd(int fd);

void _log_launchd_bug(const char *rcs_rev, const char *path, unsigned int line, const char *test);

bool progeny_check(pid_t p);

#endif
