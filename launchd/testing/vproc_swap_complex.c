#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <vproc.h>
#include <vproc_priv.h>

static void my_callback(const launch_data_t obj, const char *key, void *context);

int main(void)
{
	launch_data_t output_obj = NULL;

	assert(vproc_swap_complex(NULL, VPROC_GSK_ENVIRONMENT, NULL, &output_obj) == 0);

	assert(launch_data_get_type(output_obj) == LAUNCH_DATA_DICTIONARY);

	launch_data_dict_iterate(output_obj, my_callback, stdout);

	return 0;
}

void
my_callback(const launch_data_t obj, const char *key, void *context)
{
	fprintf(context, "%s == %s\n", key, launch_data_get_string(obj));
}
