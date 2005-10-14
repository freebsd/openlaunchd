#ifndef __LAUNCHD_CORE_LOGIC__
#define __LAUNCHD_CORE_LOGIC__
/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#define LAUNCHD_MIN_JOB_RUN_TIME 10
#define LAUNCHD_REWARD_JOB_RUN_TIME 60
#define LAUNCHD_FAILED_EXITS_THRESHOLD 10

struct jobcb;

#define ANY_JOB ((struct jobcb *)-1)

struct bootstrap {
	kq_callback			kqbstrap_callback;
	SLIST_ENTRY(bootstrap)		sle;
	SLIST_HEAD(, bootstrap)		sub_bstraps;
	SLIST_HEAD(, jobcb)		jobs;
	SLIST_HEAD(, machservice)	services;
	struct bootstrap		*parent;
	mach_port_name_t		bootstrap_port;
	mach_port_name_t		requestor_port;
};

struct bootstrap *bootstrap_new(struct bootstrap *parent, mach_port_name_t requestorport);
void bootstrap_delete(struct bootstrap *bootstrap);
void bootstrap_delete_anything_with_port(struct bootstrap *bootstrap, mach_port_t port);
struct machservice *bootstrap_lookup_service(struct bootstrap *bootstrap, const char *name);
void bootstrap_callback(void *obj, struct kevent *kev);

struct machservice {
	SLIST_ENTRY(machservice) sle;
	struct bootstrap	*bootstrap;
	struct jobcb		*job;
	mach_port_name_t	port;
	unsigned int		isActive:1, __junk:31;
	char			name[0];
};

struct machservice *machservice_new(struct bootstrap *bootstrap, const char *name, mach_port_t *serviceport, struct jobcb *j);
void machservice_delete(struct machservice *servicep);
void machservice_watch(struct machservice *servicep);

struct socketgroup {
	SLIST_ENTRY(socketgroup) sle;
	int *fds;
	int fd_cnt;
	char name[0];
};

bool socketgroup_new(struct jobcb *j, const char *name, int *fds, int fd_cnt);
void socketgroup_delete(struct jobcb *j, struct socketgroup *sg);
void socketgroup_watch(struct jobcb *j, struct socketgroup *sg);
void socketgroup_ignore(struct jobcb *j, struct socketgroup *sg);
void socketgroup_callback(struct jobcb *j, struct kevent *kev);
void socketgroup_setup(launch_data_t obj, const char *key, void *context);

struct watchpath {
	SLIST_ENTRY(watchpath) sle;
	int fd;
	unsigned int is_qdir:1, __junk:31;
	char name[0];
};

bool watchpath_new(struct jobcb *j, const char *name, bool qdir);
void watchpath_delete(struct jobcb *j, struct watchpath *wp);
void watchpath_watch(struct jobcb *j, struct watchpath *wp);
void watchpath_ignore(struct jobcb *j, struct watchpath *wp);
void watchpath_callback(struct jobcb *j, struct kevent *kev);

struct calendarinterval {
	SLIST_ENTRY(calendarinterval) sle;
	struct tm when;
};

bool calendarinterval_new(struct jobcb *j, struct tm *w);
void calendarinterval_delete(struct jobcb *j, struct calendarinterval *ci);
void calendarinterval_setalarm(struct jobcb *j, struct calendarinterval *ci);
void calendarinterval_callback(struct jobcb *j, struct kevent *kev);

struct envitem {
	SLIST_ENTRY(envitem) sle;
	char *value;
	char key[0];
};

bool envitem_new(struct jobcb *j, const char *k, const char *v, bool global);
void envitem_delete(struct jobcb *j, struct envitem *ei, bool global);
void envitem_setup(launch_data_t obj, const char *key, void *context);

struct limititem {
	SLIST_ENTRY(limititem) sle;
	struct rlimit lim;
	unsigned int setsoft:1, sethard:1, which:30;
};

bool limititem_update(struct jobcb *j, int w, rlim_t r);
void limititem_delete(struct jobcb *j, struct limititem *li);
void limititem_setup(launch_data_t obj, const char *key, void *context);

struct jobcb {
	kq_callback kqjob_callback;
	SLIST_ENTRY(jobcb) sle;
	SLIST_HEAD(, socketgroup) sockets;
	SLIST_HEAD(, watchpath) vnodes;
	SLIST_HEAD(, calendarinterval) cal_intervals;
	SLIST_HEAD(, envitem) global_env;
	SLIST_HEAD(, envitem) env;
	SLIST_HEAD(, limititem) limits;
	SLIST_HEAD(, machservice) machservices;
	struct bootstrap *bstrap;
	mach_port_t priv_port;
	uid_t mach_uid;
	char **argv;
	char *prog;
	char *rootdir;
	char *workingdir;
	char *username;
	char *groupname;
	char *stdoutpath;
	char *stderrpath;
	pid_t p;
	int argc;
	int last_exit_status;
	int execfd;
	int nice;
	int timeout;
	time_t start_time;
	size_t failed_exits;
	unsigned int start_interval;
	unsigned int checkedin:1, firstborn:1, debug:1, throttle:1, inetcompat:1, inetcompat_wait:1,
			ondemand:1, session_create:1, low_pri_io:1, init_groups:1, priv_port_has_senders:1,
			importing_global_env:1, importing_hard_limits:1, setmask:1, legacy_mach_job:1, __pad:1;
	mode_t mask;
	char label[0];
};

struct jobcb *job_find(const char *label);
struct jobcb *job_import(launch_data_t pload);
struct jobcb *job_new_via_mach_init(struct bootstrap *bootstrap, const char *cmd, uid_t uid, bool ond);
launch_data_t job_export(struct jobcb *j);
launch_data_t job_export_all(void);
void job_watch(struct jobcb *j);
void job_ignore(struct jobcb *j);
void job_dispatch(struct jobcb *j);
void job_start(struct jobcb *j);
void job_start_child(struct jobcb *j, int execfd) __attribute__((noreturn));
void job_setup_attributes(struct jobcb *j);
void job_stop(struct jobcb *j);
void job_checkin(struct jobcb *j);
bool job_active(struct jobcb *j);
bool job_useless(struct jobcb *j);
void job_reap(struct jobcb *j);
#ifdef PID1_REAP_ADOPTED_CHILDREN
bool job_reap_pid(pid_t p);
#endif
void job_remove(struct jobcb *j);
void job_remove_all(void);
void job_ack_port_destruction(struct jobcb *j, mach_port_t p);
void job_ack_no_senders(struct jobcb *j);
mach_port_t job_get_priv_port(struct jobcb *j);
void job_callback(void *obj, struct kevent *kev);
void job_log(struct jobcb *j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
void job_log_error(struct jobcb *j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));

extern size_t total_children;

extern struct bootstrap *root_bootstrap;
extern struct bootstrap *ws_bootstrap;
extern struct bootstrap *current_rpc_bootstrap;
extern struct jobcb *current_rpc_server;


#endif
