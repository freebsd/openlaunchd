#ifndef _LIBINITNG_H_
#define _LIBINITNG_H_

#include <stdbool.h>
#include <netdb.h>

typedef struct initng_jobinfo * initng_jobinfo_t;

struct addrinfopp {
	struct addrinfo hints;
	char nodename[1024];
	char servname[1024];
};

/* returns a fd to add to run loops to poll for readability, safe to ignore */
int initng_init(void);

bool initng_jobinfo_alloc(initng_jobinfo_t *j, char *u);
void initng_jobinfo_free(initng_jobinfo_t j);

bool initng_jobinfo_set_UserName(initng_jobinfo_t j, char *u);
bool initng_jobinfo_set_GroupName(initng_jobinfo_t j, char *g);
bool initng_jobinfo_set_EnvironmentVariables(initng_jobinfo_t j, char *envp[]);
bool initng_jobinfo_set_Enabled(initng_jobinfo_t j, bool d);
bool initng_jobinfo_set_LaunchOnce(initng_jobinfo_t j, bool lo);
bool initng_jobinfo_set_OnDemand(initng_jobinfo_t j, bool od);
bool initng_jobinfo_set_Batch(initng_jobinfo_t j, bool b);
bool initng_jobinfo_set_ServiceIPC(initng_jobinfo_t j, bool sipc);
bool initng_jobinfo_set_inetdSingleThreaded(initng_jobinfo_t j, bool st);
bool initng_jobinfo_set_PeriodicSeconds(initng_jobinfo_t j, unsigned int ps);
bool initng_jobinfo_set_SpecificTimeval(initng_jobinfo_t j, time_t stv);
bool initng_jobinfo_set_Program(initng_jobinfo_t j, char *p);
bool initng_jobinfo_set_ProgramArguments(initng_jobinfo_t j, char *argv[]);
bool initng_jobinfo_set_ServiceDescription(initng_jobinfo_t j, char *sd);
bool initng_jobinfo_set_MachServiceNames(initng_jobinfo_t j, char *msn[]);
bool initng_jobinfo_add_Socket(initng_jobinfo_t j, struct addrinfopp *ai);

#endif
