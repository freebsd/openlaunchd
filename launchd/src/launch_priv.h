#ifndef _LAUNCH_PRIV_H_
#define _LAUNCH_PRIV_H_

#define LAUNCH_KEY_GETUSERENVIRONMENT           "GetUserEnvironment"
#define LAUNCH_KEY_SETUSERENVIRONMENT           "SetUserEnvironment"
#define LAUNCH_KEY_UNSETUSERENVIRONMENT         "UnsetUserEnvironment"
#define LAUNCH_KEY_SETSTDOUT                    "SetStandardOut"
#define LAUNCH_KEY_SETSTDERR                    "SetStandardError"
#define LAUNCH_KEY_SHUTDOWN                     "Shutdown"
#define LAUNCH_KEY_GETRESOURCELIMITS            "GetResourceLimits"
#define LAUNCH_KEY_SETRESOURCELIMITS            "SetResourceLimits"
#define LAUNCH_KEY_RELOADTTYS                   "ReloadTTYS"
#define LAUNCH_KEY_SETLOGMASK                   "SetLogMask"
#define LAUNCH_KEY_GETLOGMASK                   "GetLogMask"
#define LAUNCH_KEY_SETUMASK                     "SetUmask"
#define LAUNCH_KEY_GETUMASK                     "GetUmask"
#define LAUNCH_KEY_GETRUSAGESELF                "GetResourceUsageSelf"
#define LAUNCH_KEY_GETRUSAGECHILDREN            "GetResourceUsageChildren"

#define LAUNCHD_SOCKET_ENV		"LAUNCHD_SOCKET"
#define LAUNCHD_SOCK_PREFIX		"/var/launchd"
#define LAUNCHD_TRUSTED_FD_ENV		"__LAUNCHD_FD"
#define LAUNCHD_ASYNC_MSG_KEY		"_AsyncMessage"
#define LAUNCH_KEY_BATCHCONTROL		"BatchControl"
#define LAUNCH_KEY_BATCHQUERY		"BatchQuery"

typedef struct _launch *launch_t;

launch_t launchd_fdopen(int);
int launchd_getfd(launch_t);
void launchd_close(launch_t);

launch_data_t   launch_data_new_errno(int);
bool            launch_data_set_errno(launch_data_t, int);

int launchd_msg_send(launch_t, launch_data_t);
int launchd_msg_recv(launch_t, void (*)(launch_data_t, void *), void *);

/* batch jobs will be implicity re-enabled when the last application who
 * disabled them exits */
void launchd_batch_enable(bool);
bool launchd_batch_query(void);

#endif
