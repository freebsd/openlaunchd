#ifndef _LAUNCH_PRIV_H_
#define _LAUNCH_PRIV_H_

#define LAUNCHD_SOCKET_ENV		"LAUNCHD_SOCKET"
#define LAUNCHD_DEFAULT_SOCK_PATH	"/var/launchd.socket"
#define LAUNCHD_TRUSTED_FD_ENV		"__LAUNCHD_FD"
#define LAUNCHD_ASYNC_MSG_KEY		"_AsyncMessage"
#define LAUNCH_KEY_BATCHCONTROL		"BatchControl"
#define LAUNCH_KEY_BATCHQUERY		"BatchQuery"

typedef struct _launch *launch_t;

launch_data_t launch_data_copy(launch_data_t);

launch_t launchd_fdopen(int);
int launchd_getfd(launch_t);
void launchd_close(launch_t);

int launchd_msg_send(launch_t, launch_data_t);
int launchd_msg_recv(launch_t, void (*)(launch_data_t, void *), void *);

/* batch jobs will be implicity re-enabled when the last application who
 * disabled them exits */
void launchd_batch_enable(bool);
bool launchd_batch_query(void);

#endif
