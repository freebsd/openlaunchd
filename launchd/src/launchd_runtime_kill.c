/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#if !defined(__LP64__) && !defined(__arm__)
#define _NONSTD_SOURCE 1
#define old_kill(x, y) kill(x, y)
#define old_killpg(x, y) killpg(x, y)
#else
/* ??? No blessed way to get the old behavior */
extern int __kill(int, int, int);
#define old_kill(x, y) __kill(x, y, 0)
#define old_killpg(x, y) __kill(-(x), y, 0)
#endif
#include <signal.h>

#include "launchd_runtime_kill.h"

/*
 * POSIX defines consistency over correctness, and consequently kill/killpg now
 * returns EPERM instead of ESRCH.
 *
 * I've filed 5487498 to get a non-portable kill() variant, but for now,
 * defining _NONSTD_SOURCE gets us the old behavior.
 */

int
runtime_kill(pid_t pid, int sig)
{
	return old_kill(pid, sig);
}

int
runtime_killpg(pid_t pgrp, int sig)
{
	return old_killpg(pgrp, sig);
}
