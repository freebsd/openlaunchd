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

typedef enum {
	VPROC_GSK_LAST_EXIT_STATUS = 1,
	VPROC_GSK_GLOBAL_ON_DEMAND,
	VPROC_GSK_MGR_UID,
	VPROC_GSK_MGR_PID,
	VPROC_GSK_IS_NATIVE,
	VPROC_GSK_BASIC_KEEPALIVE,
} vproc_gsk_t;

typedef void * vproc_err_t;

typedef void * vproc_t;
typedef void * vprocmgr_t;

vproc_err_t vproc_swap_integer(vproc_t vp, vproc_gsk_t key, int64_t *inval, int64_t *outval);

const char *vproc_strerror(vproc_err_t r);

#pragma GCC visibility pop

__END_DECLS

#endif
