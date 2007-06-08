#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void
test5225889(int first, int second)
{
	struct timeval tvs, tve, tvd;
	struct timespec timeout = { 30, 0 };
	struct kevent kev;
	int r, kq = kqueue();

	fprintf(stdout, "First timer %i being updated to %i.\n", first, second);

	assert(kq != -1);

	EV_SET(&kev, 0, EVFILT_TIMER, EV_ADD|EV_ONESHOT, NOTE_SECONDS, first, NULL);
	r = kevent(kq, &kev, 1, NULL, 0, NULL);
	assert(r != -1);

	EV_SET(&kev, 0, EVFILT_TIMER, EV_ADD|EV_ONESHOT, NOTE_SECONDS, second, NULL);
	r = kevent(kq, &kev, 1, NULL, 0, NULL);
	assert(r != -1);

	gettimeofday(&tvs, NULL);
	r = kevent(kq, NULL, 0, &kev, 1, &timeout);
	gettimeofday(&tve, NULL);

	timersub(&tve, &tvs, &tvd);

	fprintf(stdout, "Waited %lu seconds for kevent() to return.\n", tvd.tv_sec);

	switch (r) {
	case 1:
		assert(kev.data == second);
		assert(tvd.tv_sec >= second);
		break;
	case -1:
	case 0:
	default:
		fprintf(stderr, "Bug 5225889 still exists!\n");
		exit(EXIT_FAILURE);
	}
}

int
main(void)
{
	test5225889(5, 10);
	test5225889(10, 5);

	fprintf(stdout, "Finished.\n");

	exit(EXIT_SUCCESS);
}
