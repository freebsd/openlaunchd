#ifndef _INITNG_H_
#define _INITNG_H_

#define INITNG_SOCKET_ENV	"INITNG_SOCKET"
#define INITNG_SOCKET_DEFAULT	"/var/run/initng.socket"
#define INITNG_PROTOCOL_VERSION	1

struct initng_ipc_packet {
	int	version;
	enum	{
		INITNG_CREATE = 1, /* jobs are created disabled, must enable after configuring */
		INITNG_REMOVE,
		INITNG_SET_FLAG_ENABLED,
		INITNG_SET_FLAG_ON_DEMAND,
		INITNG_SET_FLAG_BATCH,
		INITNG_SET_FLAG_LAUNCH_ONCE,
		INITNG_SET_FLAG_SUPPORTS_MGMT,
		INITNG_SET_UID,
		INITNG_SET_GID,
		INITNG_SET_PROGRAM,
		INITNG_SET_ARGV,
		INITNG_SET_ENV,
		INITNG_SET_MACH_SERVICE_NAMES,
		INITNG_SET_PERIODIC,
		INITNG_SET_DESCRIPTION,
		INITNG_ADD_FD,	/* data is ignored by initngd, given back in GET_FD command */
		INITNG_ACK,
		INITNG_SET_FLAG_INETD_SINGLE_THREADED,
	} command;
	union {
		struct {
			char	uuid[16];
			size_t	data_len;
			char	data[0];
		};
		int return_code;
	};
};
#endif
