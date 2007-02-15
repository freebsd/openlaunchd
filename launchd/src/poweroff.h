#ifndef _POWEROFF_H_
#define _POWEROFF_H_
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

#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

#define POWEROFF_RESET	1
#define POWEROFF_UPSDELAY	2

/* Returns NULL on success. Not NULL on failure */

__attribute__((visibility("default"))) void *poweroff(uint64_t flags);

__END_DECLS

#endif
