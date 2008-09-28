
#include <stdio.h>
#include <stdbool.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

/*
 * Test case must be compiled with -I../
 */
#include "config.h"
#include "liblaunch_public.h"
#include "liblaunch_private.h"
#include "liblaunch_internal.h"
#include "launchd_ktrace.h"

#include <sys/resource.h>

void launch_data_alloc_test()
{
	launch_data_t t = launch_data_alloc(LAUNCH_DATA_ARRAY);
	CU_ASSERT_PTR_NOT_NULL(t);
	CU_ASSERT_EQUAL(launch_data_get_type(t), LAUNCH_DATA_ARRAY);
}

int main(int argc, void *argv)
{
	CU_pSuite tests = NULL;
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();
	
	tests = CU_add_suite("Liblaunch API Tests", NULL, NULL);
	if (tests == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_add_test(tests, "launch_data_alloc_test", launch_data_alloc_test);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}

