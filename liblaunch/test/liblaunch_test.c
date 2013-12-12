#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "byteswap.h"
#include <netinet/in.h>

/* Verify that we can convert a 64-bit integer to network order */
static void host2wire_test_64(void **state) {
    uint64_t host_int = 1024;
    uint64_t wire_int = host2wire(host_int);
    /* Nothing to test here on a big-endian system, and we can't verify because
     * htonll() doesn't exist */
};

/* Test we can convert a 32-bit integer to network order */
static void host2wire_test_32(void **state) {
    uint32_t host_int = 1024;
    uint32_t wire_int = htonl(host_int);
    assert_true(wire_int == host2wire(host_int));
};

/* Test we can convert a 16-bit integer to network order */
static void host2wire_test_16(void **state) {
    uint16_t host_int = 32;
    uint16_t wire_int = htons(host_int);
    assert_true(wire_int == host2wire(host_int));
};

/* Test we can (not) convert a single byte integer */
static void host2wire_test_8(void **state) {
    uint8_t host_int = 8;
    assert_true(host_int == host2wire(host_int));
};

int main(void) {
    const UnitTest tests[] = {
        unit_test(host2wire_test_64),
        unit_test(host2wire_test_32),
        unit_test(host2wire_test_16),
        unit_test(host2wire_test_8),
    };

    return run_tests(tests);
}
