#ifndef _LIBINITNG_H_
#define _LIBINITNG_H_

#include <stdarg.h>
#include <stdbool.h>


/* Unless otherwise stated, all of the following APIs return 0 on success
 * and -1 (and errno) on failure */

/* returns FD to connection, -1 and errno on failure */
int initng_open(void);
int initng_close(int fd);

typedef void (*initng_checkin_cb)(char *key, char *data[], void *cookie);
int initng_checkin(int fd, initng_checkin_cb cb, void *cookie);

/* simple synchronous APIs */

int initng_msg(int fd, char *command, ...);
int initng_msgv(int fd, char *command, va_list ap);
int initng_msga(int fd, char *command, char *data[]);

#ifdef INITNG_PRIVATE_API

/* asynchronous APIs */

typedef struct {
	pid_t	ic_pid;
	uid_t	ic_uid;
	gid_t	ic_gid;
} initng_cred_t;

typedef void (*initng_msg_cb)(int fd, char *command, char *data[], void *cookie, initng_cred_t *cred);
int initng_recvmsg(int fd, initng_msg_cb cb, void *cookie);

int initng_sendmsg(int fd, char *command, ...);
int initng_sendmsgv(int fd, char *command, va_list ap);
int initng_sendmsga(int fd, char *command, char *data[]); 

/* server support */

/* returns FD to connection, -1 and errno on failure */
int initng_server_init(const char *thepath);

/* returns FD to new connection, -1 and errno on failure */
int initng_server_accept(int lfd);

void initng_set_sniffer(int fd, bool e);
void initng_sendmsga2sniffers(char *command, char *data[]);

/* use this if you enable non-blocking IO on a FD
 * call it when the FD becomes writable with select()/kevent()
 * will return INITNG_ERR_SUCCESS once the queue is drained.
 */
int initng_flush(int fd);

#endif
#endif
