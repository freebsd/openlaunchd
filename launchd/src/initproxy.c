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
#include <getopt.h>

#include "libinitng.h"

static int kq = 0;
static void fd_cb(int fd, const char *label, void *cookie);

int main(int argc, char *argv[])
{
	static struct option longopts[] = {
		{ "inetd_st",	no_argument,	0,	's' },
		{ "inetd_mt",	no_argument,	0,	'm' },
		{ 0,		0,		0,	0 }
	};
	struct timespec timeout = { 2, 0 };
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	struct kevent kev;
	int ch, r, ec = EXIT_FAILURE;
	bool ist = false, imt = false;

	openlog(basename(argv[0]), LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);

	while ((ch = getopt_long(argc, argv, "sm", longopts, NULL)) != -1) {
		switch (ch) {
		case 'm':
			imt = true;
			break;
		case 's':
			ist = true;
			break;
		case '?':
		default:
			syslog(LOG_DEBUG, "bogus command line arguments");
			goto out;
			break;
		}
	}

	kq = kqueue();

	if (initng_fdcheckin(fd_cb, NULL) == -1) {
		syslog(LOG_DEBUG, "initng_checkin(): %s", strerror(errno));
		goto out;
	}

	for (;;) {
		if ((r = kevent(kq, NULL, 0, &kev, 1, &timeout)) == -1) {
			syslog(LOG_DEBUG, "kevent(): %m");
			goto out;
		} else if (r == 0) {
			ec = EXIT_SUCCESS;
			goto out;
		}

		if (ist) {
			if ((r = accept(kev.ident, (struct sockaddr *)&ss, &slen)) == -1) {
				if (errno == EWOULDBLOCK)
					continue;
				syslog(LOG_DEBUG, "accept(): %m");
				goto out;
			} else {
				pid_t p = fork();
				if (p == -1)
					goto out;
				if (p != 0) {
					close(r);
					continue;
				}
				dup2(r, STDIN_FILENO);
				dup2(r, STDOUT_FILENO);
				dup2(r, STDERR_FILENO);
				execv(argv[optind], argv + optind);
				exit(EXIT_FAILURE);
			}
		} else if (imt) {
			dup2(kev.ident, STDIN_FILENO);
			dup2(kev.ident, STDOUT_FILENO);
			dup2(kev.ident, STDERR_FILENO);
			execv(argv[optind], argv + optind);
			exit(EXIT_FAILURE);
		} else {
			goto out;
		}
	}

out:
	exit(ec);
}

static void fd_cb(int fd, const char *label, void *cookie)
{
	struct kevent kev;

	fcntl(fd, F_SETFD, 1);
	fcntl(fd, F_SETFL, O_NONBLOCK);

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, cookie);
	kevent(kq, &kev, 1, NULL, 0, NULL);
}
