#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <libgen.h>

#include "libinitng.h"

static int kq = 0;
static int __kevent(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);
static int _fd(int fd);

int main(int argc, char *argv[])
{
	struct timespec timeout = { 2, 0 };
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	struct kevent kev;
	initng_err_t ingerr;
	char ***config, ***tmpvv, **tmpv;
	int thefd, r;
	FILE *c;

	kq = kqueue();

	openlog(basename(argv[0]), LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);

	ingerr = initng_init(&thefd, NULL);
	if (ingerr != INITNG_ERR_SUCCESS) {
		syslog(LOG_DEBUG, "initng_init(): %s", initng_strerror(ingerr));
		exit(EXIT_FAILURE);
	}

	ingerr = initng_checkin(thefd, &config);
	if (ingerr != INITNG_ERR_SUCCESS) {
		syslog(LOG_DEBUG, "initng_checkin(): %s", initng_strerror(ingerr));
		exit(EXIT_FAILURE);
	}

	for (tmpvv = config; *tmpvv; tmpvv++) {
		tmpv = *tmpvv;
		if (!strcmp(tmpv[0], "addFD")) {
			int fd = strtol(tmpv[3], NULL, 10);
			__kevent(_fd(fd), EVFILT_READ, EV_ADD, 0, 0, NULL);
		}
	}

	initng_freeconfig(config);

	for (;;) {
		if ((r = kevent(kq, NULL, 0, &kev, 1, &timeout)) == -1) {
			syslog(LOG_DEBUG, "kevent(): %m");
			exit(EXIT_FAILURE);
		} else if (r == 0) {
			syslog(LOG_INFO, "no more work after timeout of %d second%s, exiting...",
					timeout.tv_sec, timeout.tv_sec > 1 ? "s" : "" );
			break;
		}

		if ((r = _fd(accept(kev.ident, (struct sockaddr *)&ss, &slen))) == -1) {
			syslog(LOG_DEBUG, "kevent(): %m");
			exit(EXIT_FAILURE);
		}
		syslog(LOG_INFO, "fd %d fired and returned %d", kev.ident, r);
		c = fdopen(r, "r+");
		fprintf(c, "hello worldd says howdy howdy!\n");
		fclose(c);
		close(r);
	}

	exit(EXIT_SUCCESS);
}

static int __kevent(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	EV_SET(&kev, ident, filter, flags, fflags, data, udata);
	return kevent(kq, &kev, 1, NULL, 0, NULL);
}

static int _fd(int fd)
{
	if (fd >= 0) {
		fcntl(fd, F_SETFD, 1);
		fcntl(fd, F_SETFL, O_NONBLOCK);
	}
	return fd;
}
