#ifndef _LAUNCH_H_
#define _LAUNCH_H_

#include <stddef.h>
#include <stdbool.h>


#define LAUNCH_KEY_SUBMITJOB			"SubmitJob"
#define LAUNCH_KEY_SUBMITJOBS			"SubmitJobs"
#define LAUNCH_KEY_REMOVEJOB			"RemoveJob"
#define LAUNCH_KEY_GETJOBS			"GetJobs"
#define LAUNCH_KEY_GETALLJOBS			"GetAllJobs"
#define LAUNCH_KEY_CHECKIN			"CheckIn"
#define LAUNCH_KEY_GETUSERENVIRONMENT		"GetUserEnvironment"
#define LAUNCH_KEY_SETUSERENVIRONMENT		"SetUserEnvironment"
#define LAUNCH_KEY_UNSETUSERENVIRONMENT		"UnsetUserEnvironment"

#define LAUNCH_JOBKEY_LABEL			"Label"
#define LAUNCH_JOBKEY_DISABLED			"Disabled"
#define LAUNCH_JOBKEY_ENABLED			"Enabled"
#define LAUNCH_JOBKEY_USERNAME			"UserName"
#define LAUNCH_JOBKEY_UID			"UID"
#define LAUNCH_JOBKEY_GROUPNAME			"GroupName"
#define LAUNCH_JOBKEY_GID			"GID"
#define LAUNCH_JOBKEY_SOCKETS			"Sockets"
#define LAUNCH_JOBKEY_EVENTSOURCES		"EventSources"
#define LAUNCH_JOBKEY_INETDCOMPATIBILITY	"inetdCompatibility"
#define LAUNCH_JOBKEY_PROGRAMARGUMENTS		"ProgramArguments"
#define LAUNCH_JOBKEY_PROGRAM			"Program"
#define LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES	"UserEnvironmentVariables"
#define LAUNCH_JOBKEY_ONDEMAND			"OnDemand"
#define LAUNCH_JOBKEY_BATCH			"Batch"
#define LAUNCH_JOBKEY_ROOTDIRECTORY		"RootDirectory"
#define LAUNCH_JOBKEY_WORKINGDIRECTORY		"WorkingDirectory"
#define LAUNCH_JOBKEY_SERVICEDESCRIPTION	"ServiceDescription"
#define LAUNCH_JOBKEY_ENVIRONMENTVARIABLES	"EnvironmentVariables"
#define LAUNCH_JOBKEY_PID			"PID"
#define LAUNCH_JOBKEY_UMASK			"Umask"
#define LAUNCH_JOBKEY_SOFTRESOURCELIMITS	"SoftResourceLimits"
#define LAUNCH_JOBKEY_HARDRESOURCELIMITS	"HardResourceLimits"
#define LAUNCH_JOBKEY_SERVICEIPC		"ServiceIPC"
#define LAUNCH_JOBKEY_STANDARDOUTPATH		"StandardOutPath"
#define LAUNCH_JOBKEY_STANDARDERRORPATH		"StandardErrorPath"

#define LAUNCH_JOBINETDCOMPATIBILITY_WAIT	"Wait"

#define LAUNCH_JOBKEY_RESOURCELIMIT_CORE	"Core"
#define LAUNCH_JOBKEY_RESOURCELIMIT_CPU		"CPU"
#define LAUNCH_JOBKEY_RESOURCELIMIT_DATA	"Data"
#define LAUNCH_JOBKEY_RESOURCELIMIT_FSIZE	"FileSize"
#define LAUNCH_JOBKEY_RESOURCELIMIT_MEMLOCK	"MemoryLock"
#define LAUNCH_JOBKEY_RESOURCELIMIT_NOFILE	"NumberOfFiles"
#define LAUNCH_JOBKEY_RESOURCELIMIT_NPROC	"NumberOfProcesses"
#define LAUNCH_JOBKEY_RESOURCELIMIT_RSS		"ResidentSetSize"
#define LAUNCH_JOBKEY_RESOURCELIMIT_STACK	"Stack"

#define LAUNCH_JOBSOCKETKEY_TYPE		"SockType"
#define LAUNCH_JOBSOCKETKEY_PASSIVE		"SockPassive"
#define LAUNCH_JOBSOCKETKEY_SECUREWITHKEY	"SecureSocketWithKey"
#define LAUNCH_JOBSOCKETKEY_PATHNAME		"SockPathName"
#define LAUNCH_JOBSOCKETKEY_NODENAME		"SockNodeName"
#define LAUNCH_JOBSOCKETKEY_SERVICENAME		"SockServiceName"
#define LAUNCH_JOBSOCKETKEY_FAMILY		"SockFamily"
#define LAUNCH_JOBSOCKETKEY_PROTOCOL		"SockProtocol"
#define LAUNCH_JOBSOCKETKEY_FD			"SockFD"
#define LAUNCH_JOBSOCKETKEY_ADDRINFORESULTS	"AddrinfoResults"

#define LAUNCH_JOBADDRINFOKEY_PASSIVE		"Passive"
#define LAUNCH_JOBADDRINFOKEY_FAMILY		"Family"
#define LAUNCH_JOBADDRINFOKEY_SOCKTYPE		"SockType"
#define LAUNCH_JOBADDRINFOKEY_PROTOCOL		"Protocol"
#define LAUNCH_JOBADDRINFOKEY_ADDRESS		"Address"
#define LAUNCH_JOBADDRINFOKEY_CANONICALNAME	"CanonicalName"
#define LAUNCH_JOBADDRINFOKEY_FD		"FD"

#define LAUNCH_RESPONSE_SUCCESS			"Success"
#define LAUNCH_RESPONSE_JOBNOTFOUND		"JobNotFound"
#define LAUNCH_RESPONSE_NOTRUNNINGFROMLAUNCHD	"NotRunningFromLaunchd"
#define LAUNCH_RESPONSE_MISSINGEVENTSOURCES	"MissingEventSources"
#define LAUNCH_RESPONSE_UNKNOWNCOMMAND		"UnknownCommand"
#define LAUNCH_RESPONSE_JOBEXISTS		"JobExists"
#define LAUNCH_RESPONSE_LABELMISSING		"LabelMissing"
#define LAUNCH_RESPONSE_PROGRAMARGUMENTSMISSING	"ProgramArgumentsMissing"

typedef struct _launch_data *launch_data_t;

typedef enum {
	LAUNCH_DATA_DICTIONARY = 1,
	LAUNCH_DATA_ARRAY,
	LAUNCH_DATA_FD,
	LAUNCH_DATA_INTEGER,
	LAUNCH_DATA_REAL,
	LAUNCH_DATA_BOOL,
	LAUNCH_DATA_STRING,
	LAUNCH_DATA_OPAQUE,
} launch_data_type_t;

launch_data_t		launch_data_alloc(launch_data_type_t);
launch_data_t		launch_data_copy(launch_data_t);
launch_data_type_t	launch_data_get_type(launch_data_t);
void			launch_data_free(launch_data_t);

/* kLaunchDataDictionary */
/* the value should not be changed while iterating */
bool		launch_data_dict_insert(launch_data_t, launch_data_t, const char *);
launch_data_t	launch_data_dict_lookup(launch_data_t, const char *);
bool		launch_data_dict_remove(launch_data_t, const char *);
void		launch_data_dict_iterate(launch_data_t, void (*)(launch_data_t, const char *, void *), void *);
size_t		launch_data_dict_get_count(launch_data_t);

/* kLaunchDataArray */
bool		launch_data_array_set_index(launch_data_t, launch_data_t, size_t);
launch_data_t	launch_data_array_get_index(launch_data_t, size_t);
size_t		launch_data_array_get_count(launch_data_t);

launch_data_t	launch_data_new_fd(int);
launch_data_t	launch_data_new_integer(long long);
launch_data_t	launch_data_new_bool(bool);
launch_data_t	launch_data_new_real(double);
launch_data_t	launch_data_new_string(const char *);
launch_data_t	launch_data_new_opaque(const void *, size_t);

bool		launch_data_set_fd(launch_data_t, int);
bool		launch_data_set_integer(launch_data_t, long long);
bool		launch_data_set_bool(launch_data_t, bool);
bool		launch_data_set_real(launch_data_t, double);
bool		launch_data_set_string(launch_data_t, const char *);
bool		launch_data_set_opaque(launch_data_t, const void *, size_t);

int		launch_data_get_fd(launch_data_t);
long long	launch_data_get_integer(launch_data_t);
bool		launch_data_get_bool(launch_data_t);
double		launch_data_get_real(launch_data_t);
const char *	launch_data_get_string(launch_data_t);
void *		launch_data_get_opaque(launch_data_t);
size_t		launch_data_get_opaque_size(launch_data_t);


/* launch_get_fd()
 *
 * Use this to get the FD if you're doing asynchronous I/O with select(),
 * poll() or kevent().
 */
int launch_get_fd(void);

/* launch_msg()
 *
 * Use this API to send and receive messages.
 * Calling launch_msg() with no message to send is a valid way to get
 * asynchronously received messages.
 *
 * If a message was to be sent, it returns NULL and errno on failure.
 *
 * If no messages were to be sent, it returns NULL and errno is set to zero if
 * no more asynchronous messages are available.
 */
launch_data_t launch_msg(launch_data_t);

#endif
