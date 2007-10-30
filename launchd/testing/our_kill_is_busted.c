#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int
main(void)
{
	int wstatus;
	pid_t p, wr;
	int kill_r, killpg_r, r;
	int kill_e, killpg_e;

	p = fork();
	assert(p != -1);

	if (p == 0) {
		r = setsid();
		assert(r != -1);
		_exit(EXIT_SUCCESS);
	}

	sleep(1);

	errno = 0;
	kill_r = kill(p, SIGTERM);
	kill_e = errno;

	errno = 0;
	killpg_r = kill(-(p), SIGTERM);
	killpg_e = errno;

	if (kill_r != killpg_r) {
		fprintf(stderr, "Bug. kill() is inconsistent.\n");
		fprintf(stderr, "kill(   p, SIGTERM) returned %d and errno == %d\n", kill_r, kill_e);
		fprintf(stderr, "kill(-(p), SIGTERM) returned %d and errno == %d\n", killpg_r, killpg_e);
		if (kill_e == EPERM || killpg_e == EPERM) {
			fprintf(stderr, "The kernel lied. We should have the right to kill 'p' and it returned EPERM.\n");
		}
		if (kill_e == ESRCH || killpg_e == ESRCH) {
			fprintf(stderr, "The kernel is confused. PID 'p' exists, but the kernel couldn't find it.\n");
		}

		exit(EXIT_FAILURE);
	}

	wr = waitpid(p, &wstatus, 0);
	assert(wr == p);

	exit(EXIT_SUCCESS);
}
