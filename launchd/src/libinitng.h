#ifndef _LIBINITNG_H_
#define _LIBINITNG_H_

#include <sys/socket.h>
#include <stdarg.h>
#include <stdbool.h>

typedef enum {
	INITNG_ERR_SUCCESS = 0,
	INITNG_ERR_AGAIN,
	INITNG_ERR_CONN_NOT_FOUND,
	INITNG_ERR_SYSCALL,
	INITNG_ERR_RECVMSG_CTRUNC,
	INITNG_ERR_DIRECTORY_LOOKUP,
	INITNG_ERR_BROKEN_CONN,
} initng_err_t;

const char *initng_strerror(initng_err_t error);

initng_err_t initng_init(int *fd, const char *thepath);
initng_err_t initng_close(int fd);

/* simple synchronous API */
initng_err_t initng_msg(int fd, char *command, ...);
initng_err_t initng_msgv(int fd, char *command, va_list ap);
initng_err_t initng_msga(int fd, char *command, char *data[]);

initng_err_t initng_checkin(int fd, char ****config);
void initng_freeconfig(char ***config);

#ifdef INITNG_PRIVATE_API

typedef void (*initng_msg_cb)(int fd, char *command, char *data[], void *cookie);

initng_err_t initng_recvmsg(int fd, initng_msg_cb cb, void *cookie);

initng_err_t initng_sendmsg(int fd, char *command, ...);
initng_err_t initng_sendmsgv(int fd, char *command, va_list ap);
initng_err_t initng_sendmsga(int fd, char *command, char *data[]); 

initng_err_t initng_server_init(int *fd, const char *thepath);
initng_err_t initng_server_accept(int *cfd, int lfd);

void initng_set_sniffer(int fd, bool e);
void initng_sendmsga2sniffers(char *command, char *data[]);

/* use this if you enable non-blocking IO on a FD
 * call it when the FD becomes writable with select()/kevent()
 * will return INITNG_ERR_SUCCESS once the queue is drained.
 */
initng_err_t initng_flush(int fd);

#endif
#endif
