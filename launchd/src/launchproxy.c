#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <Security/AuthSession.h>
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
#include <signal.h>

#include "launch.h"

static int kq = 0;

static void find_fds(launch_data_t o, const char *key, void *context __attribute__((unused)))
{
        struct kevent kev;
        size_t i;
	int fd;

	if (key && !strcmp(key, LAUNCH_JOBSOCKETKEY_RENDEZVOUSFD)) {
		close(launch_data_get_fd(o));
		return;
	}

        switch (launch_data_get_type(o)) {
        case LAUNCH_DATA_FD:
                fd = launch_data_get_fd(o);
		fcntl(fd, F_SETFD, 1);
                EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
                if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
                        syslog(LOG_DEBUG, "kevent(): %m");
                break;
        case LAUNCH_DATA_ARRAY:
                for (i = 0; i < launch_data_array_get_count(o); i++)
                        find_fds(launch_data_array_get_index(o, i), NULL, NULL);
                break;
        case LAUNCH_DATA_DICTIONARY:
                launch_data_dict_iterate(o, find_fds, NULL);
                break;
        default:
                break;
        }
}

int main(int argc __attribute__((unused)), char *argv[])
{
	struct timespec timeout = { 10, 0 };
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	struct kevent kev;
	int r, ec = EXIT_FAILURE;
	launch_data_t tmp, resp, msg = launch_data_alloc(LAUNCH_DATA_STRING);
	const char *prog = NULL;
	bool w = false;

	launch_data_set_string(msg, LAUNCH_KEY_CHECKIN);

	openlog(getprogname(), LOG_PERROR|LOG_PID|LOG_CONS, LOG_LAUNCHD);

	kq = kqueue();

	if ((resp = launch_msg(msg)) == NULL) {
		syslog(LOG_ERR, "launch_msg(%s): %m", LAUNCH_KEY_CHECKIN);
		goto out;
	}

	launch_data_free(msg);

	tmp = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_SOCKETS);
	if (tmp) {
		find_fds(tmp, NULL, NULL);
	} else {
		syslog(LOG_ERR, "No FDs found to answer requests on!");
		goto out;
	}

	tmp = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_TIMEOUT);
	if (tmp)
		timeout.tv_sec = launch_data_get_integer(tmp);

	tmp = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_PROGRAM);
	if (tmp)
		prog = launch_data_get_string(tmp);

	tmp = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_INETDCOMPATIBILITY);
	if (tmp) {
		tmp = launch_data_dict_lookup(tmp, LAUNCH_JOBINETDCOMPATIBILITY_WAIT);
		if (tmp)
			w = launch_data_get_bool(tmp);
	}

	if (!w)
		signal(SIGCHLD, SIG_IGN);

	for (;;) {
		if ((r = kevent(kq, NULL, 0, &kev, 1, &timeout)) == -1) {
			syslog(LOG_DEBUG, "kevent(): %m");
			goto out;
		} else if (r == 0) {
			ec = EXIT_SUCCESS;
			goto out;
		}

		if (w) {
			dup2(kev.ident, STDIN_FILENO);
			dup2(kev.ident, STDOUT_FILENO);
			dup2(kev.ident, STDERR_FILENO);
			execv(prog ? prog : argv[1], argv + 1);
			syslog(LOG_ERR, "execv(): %m");
			exit(EXIT_FAILURE);
		}

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
			if ((tmp = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_SESSIONCREATE)) && launch_data_get_bool(tmp)) {
				if (SessionCreate) {
					if (SessionCreate(0, 0) != noErr)
						syslog(LOG_NOTICE, "%s: SessionCreate() failed!", prog ? prog : argv[1]);
				} else {
					syslog(LOG_NOTICE, "%s: SessionCreate == NULL!", prog ? prog : argv[1]);
				}
			}
			fcntl(r, F_SETFL, 0);
			dup2(r, STDIN_FILENO);
			dup2(r, STDOUT_FILENO);
			dup2(r, STDERR_FILENO);
			signal(SIGCHLD, SIG_DFL);
			execv(prog ? prog : argv[1], argv + 1);
			syslog(LOG_ERR, "execv(): %m");
			exit(EXIT_FAILURE);
		}
	}

out:
	exit(ec);
}
