#ifndef __LAUNCHD_H__
#define __LAUNCHD_H__

#include <sys/event.h>

typedef void (*kq_callback)(void *, struct kevent *);

extern kq_callback kqsimple_zombie_reaper;
extern mach_port_t launchd_bootstrap_port;

int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);

void init_boot(bool sflag, bool vflag, bool xflag, bool bflag); 
void init_pre_kevent(void);
bool init_check_pid(pid_t, int);

void update_ttys(void);
void catatonia(void);
void death(void);

#endif
