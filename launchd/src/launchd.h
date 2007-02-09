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
#ifndef __LAUNCHD_H__
#define __LAUNCHD_H__

#include <mach/mach.h>
#include <mach/port.h>
#include "liblaunch_public.h"
#include "libbootstrap_public.h"
#include "launchd_runtime.h"

#define READCONF_LABEL "com.apple.launchd.readconfig"

struct kevent;
struct conncb;

extern sigset_t blocked_signals;
extern bool debug_shutdown_hangs;
extern bool network_up;
extern int batch_disabler_count;
extern mach_port_t inherited_bootstrap_port;

bool init_check_pid(pid_t);

void batch_job_enable(bool e, struct conncb *c);

launch_data_t launchd_setstdio(int d, launch_data_t o);
void launchd_SessionCreate(void);
void launchd_shutdown(void);
void launchd_single_user(void);
void launchd_post_kevent(void);
pid_t launchd_fork(void);
boolean_t launchd_mach_ipc_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply);

void init_boot(bool sflag);
void init_pre_kevent(void);

void mach_start_shutdown(void);
void mach_init_init(mach_port_t);

int _fd(int fd);

#endif
