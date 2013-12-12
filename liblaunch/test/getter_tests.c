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

#include "liblaunch_test.h"

/*
 * TEST: launch_data_get_errno
 *****************************************************/
void test_launch_data_get_errno_null(void **state) {
    launch_data_t d = NULL;
    assert_int_equal(0, launch_data_get_errno(d));
};

void test_launch_data_get_errno(void **state) {
    struct _launch_data d;
    d.err = 4;
    assert_int_equal(4, launch_data_get_errno(&d));
}
/*****************************************************/

/* TEST: launch_data_get_fd
 *****************************************************/
void test_launch_data_get_fd_null(void **state) {
    launch_data_t d = NULL;
    assert_int_equal(0, launch_data_get_fd(d));
};

/* TEST: launch_data_get_integer
 *****************************************************/
void test_launch_data_get_integer_null(void **state) {
    launch_data_t d = NULL;
    assert_true(0 == launch_data_get_integer(d));
}

void test_launch_data_get_integer(void **state) {
    struct _launch_data d;
    d.number = 7;
    assert_true(7 == launch_data_get_integer(&d));
};
/*****************************************************/


/* TEST: launch_data_get_bool
 *****************************************************/
void test_launch_data_get_bool(void **state) {
};
/*****************************************************/
