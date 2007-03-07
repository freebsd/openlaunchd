#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <vproc.h>

int main(void)
{
	int64_t val;
	bool is_native;
	pid_t p;
	uid_t u;

	/* we assign val to p or u due to 64 bit to 32 bit trucation */

	assert(vproc_swap_integer(NULL, VPROC_GSK_MGR_PID, NULL, &val) == NULL);
	p = val;

	assert(vproc_swap_integer(NULL, VPROC_GSK_MGR_UID, NULL, &val) == NULL);
	u = val;

	assert(vproc_swap_integer(NULL, VPROC_GSK_IS_NATIVE, NULL, &val) == NULL);
	is_native = val;

	fprintf(stdout, "UID = %u PID = %u Native = %u\n", u, p, is_native);

	return 0;
}
