
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

int data_types[] = {LAUNCH_DATA_ARRAY,
					LAUNCH_DATA_DICTIONARY,
					LAUNCH_DATA_FD,
					LAUNCH_DATA_INTEGER,
					LAUNCH_DATA_REAL,
					LAUNCH_DATA_BOOL,
					LAUNCH_DATA_STRING,
					LAUNCH_DATA_OPAQUE,
					LAUNCH_DATA_ERRNO,
					LAUNCH_DATA_MACHPORT};


/*
 * Sanity-check that we can properly allocate all the different launch_data_type_t types
 */
void launch_data_alloc_test()
{
	for (int i = 0; i < (sizeof(data_types) / sizeof(data_types[0])); ++i)
	{
		launch_data_type_t type = data_types[i];
		launch_data_t t = launch_data_alloc(type);
		CU_ASSERT_PTR_NOT_NULL(t);
		CU_ASSERT_EQUAL(launch_data_get_type(t), type);
	}
}

/*
 * Sanity-check that we can properly free() all the different launch_data_type_t types
 */
void launch_data_free_test()
{
	for (int i = 0; i < (sizeof(data_types) / sizeof(data_types[0])); ++i)
	{
		launch_data_type_t type = data_types[i];
		launch_data_t t = launch_data_alloc(type);
		CU_ASSERT_PTR_NOT_NULL(t);
		void *pre_t = t;
		launch_data_free(t);
		CU_ASSERT(pre_t == t);
	}
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
	CU_add_test(tests, "launch_data_free_test", launch_data_free_test);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}

