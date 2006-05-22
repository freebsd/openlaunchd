#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <launch.h>
#include <launch_priv.h>

int
main(int argc, const char *const *argv)
{
	struct timeval tvs, tve, tvd;
	mach_port_t mpo = MACH_PORT_NULL;
	int wstatus;
	pid_t p;

	struct spawn_via_launchd_attr attrs;
	memset(&attrs, 0, sizeof(attrs));
	attrs.spawn_flags = SPAWN_VIA_LAUNCHD_STOPPED; // | SPAWN_VIA_LAUNCHD_FORCE_PPC;
	attrs.spawn_observer_port = &mpo;
#if 0
	const char *const env[] = { "FOO=bar", "ROCK=roll", NULL };
	attrs.spawn_path = "/bin/booger";
	attrs.spawn_chdir = "/Users/me";
	attrs.spawn_env = env;
#endif

	gettimeofday(&tvs, NULL);
	p = spawn_via_launchd("com.example.booger", argv + 1, &attrs);

	if (p == -1) {
		fprintf(stderr, "spawn_via_launchd(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	kill(p, SIGCONT);
	gettimeofday(&tve, NULL);
	timersub(&tve, &tvs, &tvd);
	fprintf(stdout, "p == %d mpo = 0x%x in %ld usec\n", p, mpo, tvd.tv_sec * 1000000 + tvd.tv_usec);

	assert(mpm_wait(mpo, &wstatus) == 0);

	fprintf(stdout, "wstatus == %d\n", wstatus);

	exit(EXIT_SUCCESS);
}
