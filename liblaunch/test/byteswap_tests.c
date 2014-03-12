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
 * TEST: host2wire
 *****************************************************/
void test_host2wire_64(void **state) {
	/*
    uint64_t host_int = 1024;
    uint64_t wire_int = host2wire(host_int);
	*/
    /* Nothing to test here on a big-endian system, and we can't verify because
     * htonll() doesn't exist */
};

void test_host2wire_32(void **state) {
    uint32_t host_int = 1024;
    uint32_t wire_int = htonl(host_int);
    assert_true(wire_int == host2wire(host_int));
};

void test_host2wire_16(void **state) {
    uint16_t host_int = 32;
    uint16_t wire_int = htons(host_int);
    assert_true(wire_int == host2wire(host_int));
};

void test_host2wire_8(void **state) {
    uint8_t host_int = 8;
    assert_true(host_int == host2wire(host_int));
};
/*****************************************************/

#include <stdio.h>
/*
 * TEST: wire2host
 *****************************************************/
void test_wire2host_64(void **s) {
    uint64_t wire_int = htobe64(1024);
    uint64_t host_int = 1024;
    assert_true(host_int == wire2host(wire_int));
};

void test_wire2host_32(void **s) {
    uint32_t wire_int = htonl(32);
    uint32_t host_int = 32;
    assert_true(host_int == wire2host(wire_int));
};

void test_wire2host_16(void **s) {
    uint16_t wire_int = htons(32);
    uint16_t host_int = 32;
    assert_true(host_int == wire2host(wire_int));
};

void test_wire2host_8(void **s) {
    uint8_t host_int = 8;
    assert_true(host_int = wire2host(host_int));
};
 /****************************************************/
