#ifndef _LAUNCH_PRIV_H_
#define _LAUNCH_PRIV_H_

#define LAUNCHD_SOCKET_ENV "LAUNCHD_SOCKET"

typedef struct _launch *launch_t;

launch_data_t launch_data_copy(launch_data_t);

launch_t launchd_fdopen(int);
int launchd_getfd(launch_t);
void launchd_close(launch_t);

int launchd_msg_send(launch_t, launch_data_t);
int launchd_msg_recv(launch_t, void (*)(launch_data_t, void *), void *);

#endif
