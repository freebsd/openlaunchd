#include <launch.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void print_mach_service(launch_data_t obj, const char *key, void *context)
{
	if (launch_data_get_type(obj) == LAUNCH_DATA_MACHPORT) {
		fprintf(stdout, "%s: %d\n", key, launch_data_get_machport(obj));
		mach_port_deallocate(mach_task_self(), launch_data_get_machport(obj));
		mach_port_mod_refs(mach_task_self(), launch_data_get_machport(obj), MACH_PORT_RIGHT_RECEIVE, -1);
	} else {
		fprintf(stdout, "%s: not a mach port\n", key);
	}
}

int main(void)
{
	launch_data_t resp, tmp, msg = launch_data_new_string(LAUNCH_KEY_CHECKIN);

	resp = launch_msg(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		errno = launch_data_get_errno(resp);
		fprintf(stderr, "launch_msg() response: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	tmp = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_MACHSERVICES);

	if (tmp == NULL) {
		fprintf(stderr, "no mach services found!\n");
		exit(EXIT_FAILURE);
	}

	launch_data_dict_iterate(tmp, print_mach_service, NULL);

	sleep(1);
	exit(EXIT_SUCCESS);
}
