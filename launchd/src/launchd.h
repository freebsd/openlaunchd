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

#define SHUTDOWN_LOG_DIR "/var/log/shutdown"

struct kevent;
struct conncb;

extern bool shutdown_in_progress;
extern bool fake_shutdown_in_progress;
extern bool network_up;

bool init_check_pid(pid_t);

launch_data_t launchd_setstdio(int d, launch_data_t o);
void launchd_SessionCreate(void);
void launchd_shutdown(void);
void launchd_single_user(void);
boolean_t launchd_mach_ipc_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply);

void mach_start_shutdown(void);

int _fd(int fd);

#endif
