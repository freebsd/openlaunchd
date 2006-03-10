#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <launch.h>
#include <launch_priv.h>

int
main(int argc, const char *const *argv)
{
	pid_t p;

#if 0
	const char *const env[] = { "FOO=bar", "ROCK=roll", NULL };
	struct spawn_via_launchd_attr attrs;
	memset(&attrs, 0, sizeof(attrs));
	attrs.spawn_path = "/bin/booger";
	attrs.spawn_chdir = "/Users/me";
	attrs.spawn_env = env;
#endif

	p = spawn_via_launchd("com.example.booger", argv + 1, NULL);

	if (p == -1) {
		fprintf(stderr, "spawn_via_launchd(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	fprintf(stdout, "p == %d\n", p);

	exit(EXIT_SUCCESS);
}
