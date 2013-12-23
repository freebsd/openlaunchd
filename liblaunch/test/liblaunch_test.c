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

#include <stdio.h>
#include "liblaunch_test.h"


#include "launch_priv.h"
#include "launch_internal.h"
/* Verify _launch_init_globals() properly sets up a given launch_globals_t */
void test_launch_init_globals(void **s) {
    struct launch_globals_s data;
    void *prev_ptr = data.lc_mtx;
    fprintf(stderr, "data.lc_mtx = %p deref: %p \n", data.lc_mtx, prev_ptr);
    _launch_init_globals(&data);
    fprintf(stderr, "data.lc_mtx = %p deref: %p\n", data.lc_mtx, prev_ptr);
    assert_false(data.lc_mtx == prev_ptr);
};

int main(void) {
    const UnitTest tests[] = {
	unit_test(test_host2wire_64),
	unit_test(test_host2wire_32),
	unit_test(test_host2wire_16),
	unit_test(test_host2wire_8),
	unit_test(test_wire2host_64),
	unit_test(test_wire2host_32),
	unit_test(test_wire2host_16),
	unit_test(test_wire2host_8),
	unit_test(test_launch_data_get_errno_null),
	unit_test(test_launch_data_get_errno),
	unit_test(test_launch_data_get_fd_null),
	unit_test(test_launch_data_get_integer_null),
	unit_test(test_launch_data_get_integer),
	unit_test(test_launch_data_get_bool_default),
	unit_test(test_launch_data_get_bool_false),
	unit_test(test_launch_init_globals),
    };

    return run_tests(tests);
}
