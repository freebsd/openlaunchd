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
	int ch, thefd, r, ec = EXIT_FAILURE;
	FILE *c;
	bool cf = false, lf = false, wf = false;

	openlog(basename(argv[0]), LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);

	while ((ch = getopt(argc, argv, "clw")) != -1) {
		switch (ch) {
		case 'c':
			cf = true;
			break;
		case 'l':
			lf = true;
			break;
		case 'w':
			wf = true;
			break;
		case '?':
		default:
			syslog(LOG_DEBUG, "bogus command line arguments");
			goto out;
			break;
		}
	}

	if ((cf && lf) || (!cf && !lf)) {
		syslog(LOG_DEBUG, "connect OR listen, not both and not neither, %d %d ", cf, lf);
		goto out;
	}

	kq = kqueue();


	ingerr = initng_init(&thefd, NULL);
	if (ingerr != INITNG_ERR_SUCCESS) {
		syslog(LOG_DEBUG, "initng_init(): %s", initng_strerror(ingerr));
		goto out;
	}

	ingerr = initng_checkin(thefd, &config);
	if (ingerr != INITNG_ERR_SUCCESS) {
		syslog(LOG_DEBUG, "initng_checkin(): %s", initng_strerror(ingerr));
		goto out;
	}

	for (tmpvv = config; *tmpvv; tmpvv++) {
		tmpv = *tmpvv;
		if (!strcmp(tmpv[0], "addFD")) {
			int fd = strtol(tmpv[3], NULL, 10);
			__kevent(_fd(fd), EVFILT_READ, EV_ADD, 0, 0, NULL);
		}
	}

	initng_freeconfig(config);
	initng_close(thefd);

	for (;;) {
		if ((r = kevent(kq, NULL, 0, &kev, 1, &timeout)) == -1) {
			syslog(LOG_DEBUG, "kevent(): %m");
			goto out;
		} else if (r == 0) {
			ec = EXIT_SUCCESS;
			goto out;
		}

		if (lf) {
			if ((r = _fd(accept(kev.ident, (struct sockaddr *)&ss, &slen))) == -1) {
				syslog(LOG_DEBUG, "accept(): %m");
				goto out;
			} else {
				c = fdopen(r, "r+");
				if (wf) {
					fprintf(c, "hello worldd says howdy howdy!\n");
				} else {
					char buf[4096];
					fread(buf, sizeof(buf), 1, c);
					buf[4095] = '\0';
					syslog(LOG_INFO, "received this message: %s", buf);
				}
				fclose(c);
			}
		} else {
			c = fdopen(kev.ident, "r+");
			if (wf) {
				fprintf(c, "hello worldd says howdy howdy!\n");
			} else {
				char buf[4096];
				fread(buf, sizeof(buf), 1, c);
				buf[4095] = '\0';
				syslog(LOG_INFO, "received this message: %s", buf);
			}
			fclose(c);
		}
	}

out:
	exit(ec);
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
