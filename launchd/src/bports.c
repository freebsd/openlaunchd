#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int main(int argc, char *const argv[])
{
	kern_return_t result;
	mach_port_t last_bport, bport = bootstrap_port;
	name_array_t service_names;
	unsigned int i, service_cnt, server_cnt, service_active_cnt;
	name_array_t server_names;
	boolean_t *service_actives;
	task_t task = mach_task_self();
	int srvwidth = 0;

	if (argc == 2) {
		bool getrootbs = strcmp(argv[1], "/") == 0;
		if (strcmp(argv[1], "..") == 0 || getrootbs) {
			do {
				last_bport = bport;
				result = bootstrap_parent(last_bport, &bport);

				if (result == BOOTSTRAP_NOT_PRIVILEGED) {
					fprintf(stderr, "Permission denied\n");
					exit(EXIT_FAILURE);
				} else if (result != BOOTSTRAP_SUCCESS) {
					fprintf(stderr, "bootstrap_parent() %d\n", result);
					exit(EXIT_FAILURE);
				}
			} while (getrootbs && last_bport != bport);
		} else {
			int pid = atoi(argv[1]);

			result = task_for_pid(mach_task_self(), pid, &task);

			if (result != KERN_SUCCESS) {
				fprintf(stderr, "task_for_pid() %s\n", mach_error_string(result));
				exit(EXIT_FAILURE);
			}

			result = task_get_bootstrap_port(task, &bport);

			if (result != KERN_SUCCESS) {
				fprintf(stderr, "Couldn't get bootstrap port: %s\n", mach_error_string(result));
				exit(EXIT_FAILURE);
			}
		}
	}

	if (bport == MACH_PORT_NULL) {
		fprintf(stderr, "Invalid bootstrap port\n");
		exit(EXIT_FAILURE);
	}

	result = bootstrap_info(bport, &service_names, &service_cnt,
			&server_names, &server_cnt, &service_actives, &service_active_cnt);
	if (result != BOOTSTRAP_SUCCESS) {
		fprintf(stderr, "bootstrap_info(): %d\n", result);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < service_cnt; i++) {
		int l = strlen(service_names[i]);
		if (server_names[i][0] == '\0')
			continue;
		if (l > srvwidth)
			srvwidth = l;
	}

#define bport_state(x)	(((x) == BOOTSTRAP_STATUS_ACTIVE) ? "A" : ((x) == BOOTSTRAP_STATUS_ON_DEMAND) ? "D" : "I")
#define print_srv()	fprintf(stdout, "%-3s%s\n", bport_state((service_actives[i])), service_names[i])
#define print_srvr()	fprintf(stdout, "%-3s%-*s\t%s\n", bport_state((service_actives[i])), srvwidth, service_names[i], server_names[i])

	for (i = 0; i < service_cnt ; i++) {
		if (server_names[i][0] != '\0')
			print_srvr();
	}
	for (i = 0; i < service_cnt ; i++) {
		if (server_names[i][0] == '\0')
			print_srv();
	}

	exit(EXIT_SUCCESS);
}
