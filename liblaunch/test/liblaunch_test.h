/*
 * Copyright (c) 2013 R. Tyler Croy, All rights reserved.
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
 */

#ifndef _LIBLAUNCH_TEST_H_
#define _LIBLAUNCH_TEST_H_

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "launch.h"
#include "byteswap.h"
#include <netinet/in.h>

/* byteswap.h */
void test_host2wire_64(void**);
void test_host2wire_32(void**);
void test_host2wire_16(void**);
void test_host2wire_8(void**);

void test_wire2host_64(void**);
void test_wire2host_32(void**);
void test_wire2host_16(void**);
void test_wire2host_8(void**);

/* getters.c */
void test_launch_data_get_errno_null(void**);
void test_launch_data_get_errno(void**);
void test_launch_data_get_fd_null(void**);
void test_launch_data_get_integer_null(void**);
void test_launch_data_get_integer(void**);
void test_launch_data_get_bool_default(void**);
void test_launch_data_get_bool_false(void**);

/* liblaunch.c */
void test_launch_init_globals(void**);
void test_launch_data_alloc(void**);
void test_launch_data_alloc_array(void**);

#endif
