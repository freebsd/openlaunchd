#ifndef __LAUNCHD_H__
#define __LAUNCHD_H__

typedef void (*kq_callback)(void *, struct kevent *);

extern int mainkq;
extern kq_callback kqsimple_zombie_reaper;

int __kevent(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, kq_callback *cback);
void simple_zombie_reaper(void *, struct kevent *);

void init_boot(bool sflag, bool vflag, bool xflag, bool bflag); 
void init_pre_kevent(void);
bool init_check_pid(pid_t, int);

void update_ttys(void);
void catatonia(void);
void death(void);

#endif