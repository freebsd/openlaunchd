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

#include "launch.h"

static void launch_print_obj(launch_data_t o, FILE *w);

int main(int argc __attribute__((unused)), char *argv[])
{
	int r, kq = kqueue();
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	struct kevent kev;
	FILE *c;
	size_t i;
	launch_data_t resp, tmpi, tmp, msg = launch_data_alloc(LAUNCH_DATA_STRING);

	launch_data_set_string(msg, "CheckIn");

	openlog(basename(argv[0]), LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);

	if ((resp = launch_msg(msg)) == NULL) {
		syslog(LOG_DEBUG, "launch_msg(\"CheckIn\"): %m");
		exit(EXIT_FAILURE);
	}

	tmp = launch_data_dict_lookup(resp, "Listeners");

	for (i = 0; i < launch_data_array_get_count(tmp); i++) {
		tmpi = launch_data_array_get_index(tmp, i);
		EV_SET(&kev, launch_data_get_fd(tmpi), EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
			syslog(LOG_DEBUG, "kevent(): %m");
	}

	launch_data_free(resp);

	if ((r = kevent(kq, NULL, 0, &kev, 1, NULL)) == -1) {
		syslog(LOG_DEBUG, "kevent(): %m");
		exit(EXIT_FAILURE);
	} else if (r == 0) {
		exit(EXIT_SUCCESS);
	}
	if ((r = accept(kev.ident, (struct sockaddr *)&ss, &slen)) == -1) {
		syslog(LOG_DEBUG, "accept(): %m");
		exit(EXIT_FAILURE);
	}


	c = fdopen(r, "r+");

	fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n");
		        
	fprintf(c, "<html>\n<body>\n<pre>\n");

	if (geteuid() == 0)
		launch_data_set_string(msg, "GetAllJobs");
	else
		launch_data_set_string(msg, "GetJobs");

	resp = launch_msg(msg);

	launch_print_obj(resp, c);

	fprintf(c, "</pre>\n</body>\n</html>\n");

	fclose(c);

	exit(EXIT_SUCCESS);
}

static void launch_print_obj(launch_data_t o, FILE *w)
{
        char prefix[20] = "";
        size_t i;
        int j;
        static int depth = 0;
	void launch_print_obj_dict_callback(launch_data_t obj, const char *key, void *context __attribute__((unused))) {
		fprintf(w, "%s{ %s }\n", prefix, key);
		launch_print_obj(obj, w);
	}

        for (j = 0; j < depth; j++)
                prefix[j] = '\t';
        depth++;

        switch (launch_data_get_type(o)) {
        case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, launch_print_obj_dict_callback, NULL);
                break;
        case LAUNCH_DATA_ARRAY:
                for (i = 0; i < launch_data_array_get_count(o); i++) {
                        fprintf(w, "%s[%zu]\n", prefix, i);
                        launch_print_obj(launch_data_array_get_index(o, i), w);
                }
                break;
        case LAUNCH_DATA_INTEGER:
                fprintf(w, "%sNumber: %lld\n", prefix, launch_data_get_integer(o));
                break;
        case LAUNCH_DATA_REAL:
                fprintf(w, "%sFloat: %f\n", prefix, launch_data_get_real(o));
                break;
        case LAUNCH_DATA_STRING:
                fprintf(w, "%sString: %s\n", prefix, launch_data_get_string(o));
                break;
        case LAUNCH_DATA_OPAQUE:
                fprintf(w, "%sOpaque: %p size %zu\n", prefix, launch_data_get_opaque(o), launch_data_get_opaque_size(o));
                break;
        case LAUNCH_DATA_FD:
                fprintf(w, "%sFD: %d\n", prefix, launch_data_get_fd(o));
                break;
        case LAUNCH_DATA_BOOL:
                fprintf(w, "%sBool: %s\n", prefix, launch_data_get_bool(o) ? "true" : "false");
                break;
        default:
                fprintf(w, "%stype %d is unknown\n", prefix, launch_data_get_type(o));
                break;
        }

        depth--;
        prefix[depth] = '\0';
}
