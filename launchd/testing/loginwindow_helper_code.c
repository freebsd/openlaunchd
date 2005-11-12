#include <mach/port.h>
#include <servers/bootstrap.h>
#include <unistd.h>
#include <launch.h>
#include <launch_priv.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int main(void)
{
	mach_port_t oldbsport = bootstrap_port;
	pid_t p;

	if (getuid() != 0) {
		fprintf(stderr, "This test tool must be run as root.\n");
		exit(EXIT_FAILURE);
	}

	p = create_and_switch_to_per_session_launchd("www");

	if (p > 0) {
		fprintf(stdout, "Our PID: %d\n", getpid());
		fprintf(stdout, "Per session launchd PID: %d\n", p);
		fprintf(stdout, "Old bootstrap port: 0x%x\n", oldbsport);
		fprintf(stdout, "New bootstrap port: 0x%x\n", bootstrap_port);
		for (;;) {
			pause();
		}
	} else if (p == -1) {
		fprintf(stderr, "create_and_switch_to_per_session_launchd() failed: %s\n", strerror(errno));
	} else if (p == 0) {
		fprintf(stderr, "create_and_switch_to_per_session_launchd() returned zero?!?\n");
	}
	exit(EXIT_FAILURE);
}
