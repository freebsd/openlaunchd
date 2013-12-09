#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void setup(void **state) {
    int *answer = malloc(sizeof(int));

    assert_non_null(answer);
    *answer = 42;

    *state = answer;
}

static void teardown(void **state) {
    free(*state);
}

/* A test case that does nothing and succeeds. */
static void null_test_success(void **state) {
    (void) state;
}

/* A test case that does check if an int is equal. */
static void int_test_success(void **state) {
    int *answer = *state;

    assert_int_equal(*answer, 42);
}


int main(void) {
    const UnitTest tests[] = {
        unit_test(null_test_success),
        unit_test_setup_teardown(int_test_success, setup, teardown),
    };

    return run_tests(tests);
}
