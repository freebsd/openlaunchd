/*
 * <rdar://problem/4437060> EVFILT_READ doesn't fire reliably
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static void do_parent(int thefd);
static void do_child(int thefd);

int main(void)
{
	int sp[2];

	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
		fprintf(stderr, "socketpair(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	switch (fork()) {
	case -1:
		fprintf(stderr, "fork(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	case 0:
		close(sp[0]);
		do_child(sp[1]);
		break;
	default:
		close(sp[1]);
		do_parent(sp[0]);
		break;
	}

	exit(EXIT_SUCCESS);
}

void
do_child(int thefd)
{
	char junk = '\0';

	for (;;) {
		if (-1 == write(thefd, &junk, sizeof(junk))) {
			fprintf(stderr, "%d: write(): %s\n", __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (-1 == read(thefd, &junk, sizeof(junk))) {
			fprintf(stderr, "%d: read(): %s\n", __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

void
do_parent(int thefd)
{
	struct timespec timeout = { 5, 0 };
	int iter = 0, kq;
	struct kevent kev;
	char junk = '\0';

	if (-1 == (kq = kqueue())) {
		fprintf(stderr, "kqueue(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	EV_SET(&kev, thefd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (-1 == kevent(kq, &kev, 1, NULL, 0, NULL)) {
		fprintf(stderr, "%d: kevent(): %s\n", __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (;;) {
		switch (kevent(kq, NULL, 0, &kev, 1, &timeout)) {
		case -1:
			fprintf(stderr, "%d: kevent(): %s\n", __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		case 0:
			fprintf(stderr, "After %d iterations, 4437060 still exists!\n", iter);
			exit(EXIT_FAILURE);
		case 1:
			break;
		default:
			fprintf(stderr, "kevent should only return -1, 0 or 1 for this case!\n");
			exit(EXIT_FAILURE);
		}

		if (kev.filter != EVFILT_READ) {
			fprintf(stderr, "kevent should return EVFILT_READ!\n");
			exit(EXIT_FAILURE);
		}

		if (-1 == read(thefd, &junk, sizeof(junk))) {
			fprintf(stderr, "read(): %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (-1 == write(thefd, &junk, sizeof(junk))) {
			fprintf(stderr, "%d: write(): %s\n", __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}
		iter++;
	}
}
