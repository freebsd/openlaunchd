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
#include <sys/types.h>

__BEGIN_DECLS

#pragma GCC visibility push(default)

typedef void * vproc_err_t;

typedef void * vproc_t;
typedef void * vprocmgr_t;

const char *vproc_strerror(vproc_err_t r);

/*!
 * @header      vproc
 *
 * Processes have two reference counts associated with them:
 *
 * Dirty	Tracks dirty data that needs to be flushed later.
 * Standby	Tracks any case where future work is expected.
 *
 * Processes that have no dirty data are called "clean."
 * Processes that are not standing by are called "idle."
 *
 * These two reference counts are used to prevent the application from
 * prematurely exiting.
 *
 * Sometimes, the operating system needs processes to exit. Unix has two
 * primary signals to kill applications:
 *
 * SIGKILL	Not catchable by the application.
 * SIGTERM	Catchable by the application.
 *
 * If a process is clean, the operating system is free to SIGKILL it at
 * shutdown or logout.
 *
 * If a process is clean and idle, the operating system may send SIGKILL after
 * a application specified timeout.
 *
 * If a process is dirty and idle, the operating system may send SIGTERM after
 * a application specified timeout.
 *
 *
 * launchd jobs should update their property lists accordingly.
 *
 * LaunchServicese uses private API to coordinate whether GUI applications
 * have opted into this design.
 */

/*!
 * @function vproc_dirty_retain
 *
 * @abstract
 * Call this API before creating data that needs to be saved via I/O later.
 */
void
vproc_dirty_retain(void);

/*!
 * @function vproc_dirty_release
 *
 * @abstract
 * Call this API after the dirty data has either been flushed or otherwise resolved.
 */
void
vproc_dirty_release(void);

/*!
 * @function vproc_dirty_count
 *
 * @result
 * Zero if the program is clean. Non-zero if the program contains dirty data.
 *
 * @abstract
 * A simple API to discover whether the program is dirty or not.
 */
size_t
vproc_dirty_count(void);

/*!
 * @function vproc_standby_retain
 *
 * @abstract
 * Call this API when registering notfications. For example: timers network
 * state change, or when monitoring keyboard/mouse events.
 */
void vproc_standby_retain(void);

/*!
 * @function vproc_standby_release
 *
 * @abstract
 * Call this API when deregistering notfications.
 */
void vproc_standby_release(void);

/*!
 * @function vproc_standby_count
 *
 * @result
 * Zero if the program is idle. Non-zero if the program contains outstanding event sources registered.
 *
 * @abstract
 * A simple API to discover whether the program is idle or not.
 */
size_t
size_t vproc_standby_count(void);

#pragma GCC visibility pop

__END_DECLS

#endif
