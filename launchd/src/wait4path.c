#include <sys/types.h>
#include <sys/stat.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int kq = kqueue();
	struct kevent kev;
	struct stat sb;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <object on mount point>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	EV_SET(&kev, 0, EVFILT_FS, EV_ADD, 0, 0, 0);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		fprintf(stderr, "adding EVFILT_FS to kqueue failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (;;) {
		kevent(kq, NULL, 0, &kev, 1, NULL);
		if (stat(argv[1], &sb) == 0)
			break;
	}
	
	exit(EXIT_SUCCESS);
}
