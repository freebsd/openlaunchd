#ifndef __LAUNCHD_H__
#define __LAUNCHD_H__

#include <sys/event.h>

#define HELPERD "com.apple.launchd_helperd"

typedef void (*kq_callback)(void *, struct kevent *);

extern kq_callback kqsimple_zombie_reaper;
extern mach_port_t launchd_bootstrap_port;
extern sigset_t blocked_signals;

#ifdef PID1_REAP_ADOPTED_CHILDREN
extern int pid1_child_exit_status;
#endif

int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);
void launchd_SessionCreate(const char *who);

void init_boot(bool sflag, bool vflag, bool xflag);
void init_pre_kevent(void);
bool init_check_pid(pid_t);

void update_ttys(void);
void catatonia(void);
void death(void);

#endif
