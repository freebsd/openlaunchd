#include <sys/event.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

static int kq = -1;

time_t
now_plus_n(int n)
{
	time_t later = time(NULL);

	return later + n;
}

void
add_abs_timer(int n)
{
	struct kevent kev;

	EV_SET(&kev, n * 100000, EVFILT_TIMER, EV_ADD, NOTE_SECONDS | NOTE_ABSOLUTE, now_plus_n(n), (void *)n);

	assert(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);
}

int
main(void)
{
	struct kevent kev;

	assert((kq = kqueue()) != -1);

	add_abs_timer(2);
	add_abs_timer(3);
	add_abs_timer(4);
	add_abs_timer(5);
	add_abs_timer(6);

	for (;;) {
		assert(kevent(kq, NULL, 0, &kev, 1, NULL) == 1);
		fprintf(stdout, "kev.ident == %ld kev.udata == %p\n", kev.ident, kev.udata);
		add_abs_timer((int)kev.udata);
	}

	exit(EXIT_SUCCESS);
}
