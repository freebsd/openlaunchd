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
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/boolean.h>
#include <mach/message.h>
#include <mach/notify.h>
#include <mach/mig_errors.h>
#include <mach/mach_traps.h>
#include <mach/mach_interface.h>
#include <mach/bootstrap.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/exception.h>
#include <servers/bootstrap_defs.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <paths.h>
#include <pwd.h>
#include <grp.h>
#include <ttyent.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>

#include "launch.h"
#include "launch_priv.h"
#include "launchd.h"
#include "launchd_core_logic.h"
#include "launchd_unix_ipc.h"
#include "bootstrap.h"
#include "bootstrapServer.h"

/* <rdar://problem/2685209> sys/queue.h is not up to date */
#ifndef SLIST_FOREACH_SAFE
#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SLIST_FIRST((head));				\
		(var) && ((tvar) = SLIST_NEXT((var), field), 1);	\
		(var) = (tvar))
#endif

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

struct machservice {
	SLIST_ENTRY(machservice) sle;
	struct bootstrap	*bootstrap;
	struct jobcb		*job;
	mach_port_name_t	port;
	unsigned int		isActive:1, reset:1, __junk:30;
	char			name[0];
};

static void machservice_setup(launch_data_t obj, const char *key, void *context);
static void machservice_resetport(struct jobcb *j, struct machservice *ms);


struct socketgroup {
	SLIST_ENTRY(socketgroup) sle;
	int *fds;
	unsigned int junkfds:1, fd_cnt:31;
	char name[0];
};

static bool socketgroup_new(struct jobcb *j, const char *name, int *fds, unsigned int fd_cnt, bool junkfds);
static void socketgroup_delete(struct jobcb *j, struct socketgroup *sg);
static void socketgroup_watch(struct jobcb *j, struct socketgroup *sg);
static void socketgroup_ignore(struct jobcb *j, struct socketgroup *sg);
static void socketgroup_callback(struct jobcb *j, struct kevent *kev);
static void socketgroup_setup(launch_data_t obj, const char *key, void *context);

struct watchpath {
	SLIST_ENTRY(watchpath) sle;
	int fd;
	unsigned int is_qdir:1, __junk:31;
	char name[0];
};

static bool watchpath_new(struct jobcb *j, const char *name, bool qdir);
static void watchpath_delete(struct jobcb *j, struct watchpath *wp);
static void watchpath_watch(struct jobcb *j, struct watchpath *wp);
static void watchpath_ignore(struct jobcb *j, struct watchpath *wp);
static void watchpath_callback(struct jobcb *j, struct kevent *kev);

struct calendarinterval {
	SLIST_ENTRY(calendarinterval) sle;
	struct tm when;
};

static bool calendarinterval_new(struct jobcb *j, struct tm *w);
static bool calendarinterval_new_from_obj(struct jobcb *j, launch_data_t obj);
static void calendarinterval_delete(struct jobcb *j, struct calendarinterval *ci);
static void calendarinterval_setalarm(struct jobcb *j, struct calendarinterval *ci);
static void calendarinterval_callback(struct jobcb *j, struct kevent *kev);

struct envitem {
	SLIST_ENTRY(envitem) sle;
	char *value;
	char key[0];
};

static bool envitem_new(struct jobcb *j, const char *k, const char *v, bool global);
static void envitem_delete(struct jobcb *j, struct envitem *ei, bool global);
static void envitem_setup(launch_data_t obj, const char *key, void *context);

struct limititem {
	SLIST_ENTRY(limititem) sle;
	struct rlimit lim;
	unsigned int setsoft:1, sethard:1, which:30;
};

static bool limititem_update(struct jobcb *j, int w, rlim_t r);
static void limititem_delete(struct jobcb *j, struct limititem *li);
static void limititem_setup(launch_data_t obj, const char *key, void *context);

typedef enum {
	NETWORK_UP = 1,
	NETWORK_DOWN,
	SUCCESSFUL_EXIT,
	FAILED_EXIT,
	PATH_EXISTS,
	PATH_MISSING,
	// FILESYSTEMTYPE_IS_MOUNTED,	/* for nfsiod, but maybe others */
} semaphore_reason_t;

struct semaphoreitem {
	SLIST_ENTRY(semaphoreitem) sle;
	semaphore_reason_t why;
	char what[0];
};

static bool semaphoreitem_new(struct jobcb *j, semaphore_reason_t why, const char *what);
static void semaphoreitem_delete(struct jobcb *j, struct semaphoreitem *si);
static void semaphoreitem_setup(launch_data_t obj, const char *key, void *context);
static void semaphoreitem_setup_paths(launch_data_t obj, const char *key, void *context);


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
	SLIST_HEAD(, semaphoreitem) semaphores;
	struct bootstrap *bstrap;
	mach_port_t priv_port;
	uid_t mach_uid;
	char **argv;
	char *prog;
	char *rootdir;
	char *workingdir;
	char *username;
	char *groupname;
	char *stdinpath;
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
		importing_global_env:1, importing_hard_limits:1, setmask:1, legacy_mach_job:1, runatload:1;
	mode_t mask;
	char label[0];
};

static struct jobcb *job_find2(struct bootstrap *b, const char *label);
static struct jobcb *job_import2(launch_data_t pload);
static void job_import_keys(launch_data_t obj, const char *key, void *context);
static void job_import_bool(struct jobcb *j, const char *key, bool value);
static void job_import_string(struct jobcb *j, const char *key, const char *value);
static void job_import_integer(struct jobcb *j, const char *key, long long value);
static void job_import_dictionary(struct jobcb *j, const char *key, launch_data_t value);
static void job_import_array(struct jobcb *j, const char *key, launch_data_t value);
static void job_watch(struct jobcb *j);
static void job_ignore(struct jobcb *j);
static void job_reap(struct jobcb *j);
static bool job_useless(struct jobcb *j);
static bool job_keepalive(struct jobcb *j);
static void job_start_child(struct jobcb *j, int execfd) __attribute__((noreturn));
static void job_setup_attributes(struct jobcb *j);
static bool job_setup_machport(struct jobcb *j);
static void job_callback(void *obj, struct kevent *kev);
static void job_log(struct jobcb *j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
static void job_log_error(struct jobcb *j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));


static const struct {
	const char *key;
	int val;
} launchd_keys2limits[] = {
	{ LAUNCH_JOBKEY_RESOURCELIMIT_CORE,    RLIMIT_CORE    },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_CPU,     RLIMIT_CPU     },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_DATA,    RLIMIT_DATA    },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_FSIZE,   RLIMIT_FSIZE   },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_MEMLOCK, RLIMIT_MEMLOCK },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_NOFILE,  RLIMIT_NOFILE  },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_NPROC,   RLIMIT_NPROC   },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_RSS,     RLIMIT_RSS     },
	{ LAUNCH_JOBKEY_RESOURCELIMIT_STACK,   RLIMIT_STACK   },
};

static void simple_zombie_reaper(void *, struct kevent *);

kq_callback kqsimple_zombie_reaper = simple_zombie_reaper;

static int dir_has_files(const char *path);
static char **mach_cmd2argv(const char *string);
static pid_t fork_with_bootstrap_port(mach_port_t p);
static void job_setup_env_from_other_jobs(struct bootstrap *b);

size_t total_children = 0;

void
simple_zombie_reaper(void *obj __attribute__((unused)), struct kevent *kev)
{
	waitpid(kev->ident, NULL, 0);
}

void
job_ignore(struct jobcb *j)
{
	struct socketgroup *sg;
	struct machservice *ms;
	struct watchpath *wp;

	SLIST_FOREACH(sg, &j->sockets, sle)
		socketgroup_ignore(j, sg);

	SLIST_FOREACH(wp, &j->vnodes, sle)
		watchpath_ignore(j, wp);

	SLIST_FOREACH(ms, &j->machservices, sle)
		launchd_assumes(launchd_mport_ignore(ms->port) == KERN_SUCCESS);
}

void
job_watch(struct jobcb *j)
{
	struct socketgroup *sg;
	struct machservice *ms;
	struct watchpath *wp;

	SLIST_FOREACH(sg, &j->sockets, sle)
		socketgroup_watch(j, sg);

	SLIST_FOREACH(wp, &j->vnodes, sle)
		watchpath_watch(j, wp);

	SLIST_FOREACH(ms, &j->machservices, sle)
		launchd_assumes(launchd_mport_watch(ms->port) == KERN_SUCCESS);
}

void
job_stop(struct jobcb *j)
{
	if (j->p)
		kill(j->p, SIGTERM);
}

launch_data_t
job_export(struct jobcb *j)
{
	launch_data_t tmp, tmp2, tmp3, r = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (r == NULL)
		return NULL;

	if ((tmp = launch_data_new_string(j->label)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LABEL);

	if ((tmp = launch_data_new_bool(j->ondemand)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_ONDEMAND);

	if ((tmp = launch_data_new_integer(j->last_exit_status)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LASTEXITSTATUS);

	if (j->p && (tmp = launch_data_new_integer(j->p)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PID);

	if ((tmp = launch_data_new_integer(j->timeout)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_TIMEOUT);

	if (j->prog && (tmp = launch_data_new_string(j->prog)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PROGRAM);

	if (j->stdoutpath && (tmp = launch_data_new_string(j->stdoutpath)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_STANDARDOUTPATH);

	if (j->stderrpath && (tmp = launch_data_new_string(j->stderrpath)))
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_STANDARDERRORPATH);

	if (j->argv && (tmp = launch_data_alloc(LAUNCH_DATA_ARRAY))) {
		int i;

		for (i = 0; i < j->argc; i++) {
			if ((tmp2 = launch_data_new_string(j->argv[i])))
				launch_data_array_set_index(tmp, tmp2, i);
		}

		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
	}

	if (j->inetcompat && (tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY))) {
		if ((tmp2 = launch_data_new_bool(j->inetcompat_wait)))
			launch_data_dict_insert(tmp, tmp2, LAUNCH_JOBINETDCOMPATIBILITY_WAIT);
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_INETDCOMPATIBILITY);
	}

	if (!SLIST_EMPTY(&j->sockets) && (tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY))) {
		struct socketgroup *sg;
		int i;

		SLIST_FOREACH(sg, &j->sockets, sle) {
			if ((tmp2 = launch_data_alloc(LAUNCH_DATA_ARRAY))) {
				for (i = 0; i < sg->fd_cnt; i++) {
					if ((tmp3 = launch_data_new_fd(sg->fds[i])))
						launch_data_array_set_index(tmp2, tmp3, i);
				}
				launch_data_dict_insert(tmp, tmp2, sg->name);
			}
		}

		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_SOCKETS);
	}

	if (!SLIST_EMPTY(&j->machservices) && (tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY))) {
		struct machservice *ms;

		SLIST_FOREACH(ms, &j->machservices, sle) {
			tmp2 = launch_data_new_machport(MACH_PORT_NULL);
			launch_data_dict_insert(tmp, tmp2, ms->name);
		}

		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_MACHSERVICES);
	}

	return r;
}

static void
job_remove_all_inactive2(struct bootstrap *b)
{
	struct bootstrap *sbi;
	struct jobcb *ji, *jn;

	SLIST_FOREACH(sbi, &b->sub_bstraps, sle)
		job_remove_all_inactive2(sbi);

	SLIST_FOREACH_SAFE(ji, &b->jobs, sle, jn) {
		if (!job_active(ji))
			job_remove(ji);
	}
}

void
job_remove_all_inactive(void)
{
	job_remove_all_inactive2(root_bootstrap);
}

void
job_remove(struct jobcb *j)
{
	struct calendarinterval *ci;
	struct socketgroup *sg;
	struct watchpath *wp;
	struct limititem *li;
	struct envitem *ei;
	struct machservice *ms;
	struct semaphoreitem *si;

	job_log(j, LOG_DEBUG, "Removed");

	SLIST_REMOVE(&j->bstrap->jobs, j, jobcb, sle);

	if (j->p) {
		if (kevent_mod(j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) == -1) {
			job_reap(j);
		} else {
			job_stop(j);
		}
	}

	if (j->execfd)
		launchd_assumes(close(j->execfd) == 0);

	if (j->priv_port != MACH_PORT_NULL)
		launchd_assumes(launchd_mport_close_recv(j->priv_port) == KERN_SUCCESS);

	while ((sg = SLIST_FIRST(&j->sockets)))
		socketgroup_delete(j, sg);

	while ((wp = SLIST_FIRST(&j->vnodes)))
		watchpath_delete(j, wp);

	while ((ci = SLIST_FIRST(&j->cal_intervals)))
		calendarinterval_delete(j, ci);

	while ((ei = SLIST_FIRST(&j->env)))
		envitem_delete(j, ei, false);

	while ((ei = SLIST_FIRST(&j->global_env)))
		envitem_delete(j, ei, true);

	while ((li = SLIST_FIRST(&j->limits)))
		limititem_delete(j, li);

	while ((ms = SLIST_FIRST(&j->machservices)))
		machservice_delete(ms);

	while ((si = SLIST_FIRST(&j->semaphores)))
		semaphoreitem_delete(j, si);

	if (j->prog)
		free(j->prog);

	if (j->argv)
		free(j->argv);

	if (j->rootdir)
		free(j->rootdir);

	if (j->workingdir)
		free(j->workingdir);

	if (j->username)
		free(j->username);

	if (j->groupname)
		free(j->groupname);

	if (j->stdinpath)
		free(j->stdinpath);

	if (j->stdoutpath)
		free(j->stdoutpath);

	if (j->stderrpath)
		free(j->stderrpath);

	if (j->start_interval)
		kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	free(j);
}

void
socketgroup_setup(launch_data_t obj, const char *key, void *context)
{
	launch_data_t tmp_oai;
	struct jobcb *j = context;
	unsigned int i, fd_cnt = 1;
	int *fds;

	if (launch_data_get_type(obj) == LAUNCH_DATA_ARRAY)
		fd_cnt = launch_data_array_get_count(obj);

	fds = alloca(fd_cnt * sizeof(int));

	for (i = 0; i < fd_cnt; i++) {
		if (launch_data_get_type(obj) == LAUNCH_DATA_ARRAY)
			tmp_oai = launch_data_array_get_index(obj, i);
		else
			tmp_oai = obj;

		fds[i] = launch_data_get_fd(tmp_oai);
	}

	socketgroup_new(j, key, fds, fd_cnt, strcmp(key, LAUNCH_JOBKEY_BONJOURFDS) == 0);

	ipc_revoke_fds(obj);
}

bool
job_setup_machport(struct jobcb *j)
{
	if (!launchd_assumes(launchd_mport_create_recv(&j->priv_port, j) == KERN_SUCCESS))
		goto out_bad;

	if (!launchd_assumes(launchd_mport_watch(j->priv_port) == KERN_SUCCESS))
		goto out_bad2;

	return true;
out_bad2:
	launchd_assumes(launchd_mport_close_recv(j->priv_port) == KERN_SUCCESS);
out_bad:
	return false;
}

struct jobcb *
job_new_via_mach_init(struct bootstrap *bootstrap, const char *cmd, uid_t uid, bool ond)
{
	const char **argv = (const char **)mach_cmd2argv(cmd);
	struct jobcb *j = NULL;
	char buf[1000];

	if (!launchd_assumes(argv != NULL))
		goto out_bad;

	/* preflight the string so we know how big it is */
	sprintf(buf, "via_mach_init.100000.%s", basename(argv[0]));

	j = job_new(bootstrap, buf, NULL, argv, NULL);

	free(argv);

	if (!launchd_assumes(j != NULL))
		goto out_bad;

	j->mach_uid = uid;
	j->ondemand = ond;
	j->legacy_mach_job = true;
	j->priv_port_has_senders = true; /* the IPC that called us will make-send on this port */

	if (!job_setup_machport(j))
		goto out_bad;

	if (!launchd_assumes(launchd_mport_notify_req(j->priv_port, MACH_NOTIFY_NO_SENDERS) == KERN_SUCCESS)) {
		launchd_assumes(launchd_mport_close_recv(j->priv_port) == KERN_SUCCESS);
		goto out_bad;
	}

	sprintf(j->label, "via_mach_init.%d.%s", MACH_PORT_INDEX(j->priv_port), basename(argv[0]));

	job_log(j, LOG_INFO, "New%s server in bootstrap: %x", ond ? " on-demand" : "", bootstrap->bootstrap_port);

	return j;

out_bad:
	if (j)
		job_remove(j);
	return NULL;
}

struct jobcb *
job_new(struct bootstrap *b, const char *label, const char *prog, const char *const *argv, const char *stdinpath)
{
	const char *const *argv_tmp = argv;
	char *co;
	int i, cc = 0;
	struct jobcb *j;

	if (prog == NULL && argv == NULL) {
		errno = EINVAL;
		return NULL;
	}

	j = calloc(1, sizeof(struct jobcb) + strlen(label) + 1);

	if (!launchd_assumes(j != NULL))
		goto out_bad;

	strcpy(j->label, label);
	j->kqjob_callback = job_callback;
	j->bstrap = b;
	j->ondemand = true;
	j->checkedin = true;
	j->firstborn = (strcmp(label, FIRSTBORN_LABEL) == 0);

	if (prog) {
		j->prog = strdup(prog);
		if (!launchd_assumes(j->prog != NULL))
			goto out_bad;
	}

	if (stdinpath) {
		j->stdinpath = strdup(stdinpath);
		if (!launchd_assumes(j->stdinpath != NULL))
			goto out_bad;
	}

	if (argv) {
		while (*argv_tmp++)
			j->argc++;

		for (i = 0; i < j->argc; i++)
			cc += strlen(argv[i]) + 1;

		j->argv = malloc((j->argc + 1) * sizeof(char *) + cc);

		if (!launchd_assumes(j != NULL))
			goto out_bad;

		co = ((char *)j->argv) + ((j->argc + 1) * sizeof(char *));

		for (i = 0; i < j->argc; i++) {
			j->argv[i] = co;
			strcpy(co, argv[i]);
			co += strlen(argv[i]) + 1;
		}
		j->argv[i] = NULL;
	}

	SLIST_INSERT_HEAD(&b->jobs, j, sle);

	return j;

out_bad:
	if (j) {
		if (j->prog)
			free(j->prog);
		if (j->stdinpath)
			free(j->stdinpath);
		free(j);
	}
	return NULL;
}

struct jobcb *
job_import(launch_data_t pload)
{
	struct jobcb *j = job_import2(pload);

	if (j == NULL)
		return NULL;

	job_dispatch(j);

	return j;
}

launch_data_t
job_import_bulk(launch_data_t pload)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_ARRAY);
	struct jobcb **ja;
	size_t i, c = launch_data_array_get_count(pload);

	ja = alloca(c * sizeof(struct jobcb *));

	for (i = 0; i < c; i++) {
		if ((ja[i] = job_import2(launch_data_array_get_index(pload, i))))
			errno = 0;
		launch_data_array_set_index(resp, launch_data_new_errno(errno), i);
	}

	for (i = 0; i < c; i++) {
		if (ja[i] == NULL)
			continue;
		job_dispatch(ja[i]);
	}

	return resp;
}

void
job_import_bool(struct jobcb *j, const char *key, bool value)
{
	if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE) == 0) {
		j->ondemand = !value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_ONDEMAND) == 0) {
		j->ondemand = value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_DEBUG) == 0) {
		j->debug = value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_SESSIONCREATE) == 0) {
		j->session_create = value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_LOWPRIORITYIO) == 0) {
		j->low_pri_io = value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_INITGROUPS) == 0) {
		j->init_groups = value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_RUNATLOAD) == 0) {
		j->runatload = value;
	}
}

void
job_import_string(struct jobcb *j, const char *key, const char *value)
{
	char *newstr = strdup(value);

	if (!launchd_assumes(newstr != NULL))
		return;

	if (strcasecmp(key, LAUNCH_JOBKEY_ROOTDIRECTORY) == 0) {
		j->rootdir = newstr;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_WORKINGDIRECTORY) == 0) {
		j->workingdir = newstr;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_USERNAME) == 0) {
		j->username = newstr;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_GROUPNAME) == 0) {
		j->groupname = newstr;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_STANDARDOUTPATH) == 0) {
		j->stdoutpath = newstr;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_STANDARDERRORPATH) == 0) {
		j->stderrpath = newstr;
	}
}

void
job_import_integer(struct jobcb *j, const char *key, long long value)
{
	if (strcasecmp(key, LAUNCH_JOBKEY_NICE) == 0) {
		j->nice = value;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_TIMEOUT) == 0) {
		if ((j->timeout = value) <= 0)
			j->timeout = LAUNCHD_REWARD_JOB_RUN_TIME;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_UMASK) == 0) {
		j->mask = value;
		j->setmask = true;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_STARTINTERVAL) == 0) {
		if (value <= 0) {
			job_log(j, LOG_WARNING, "StartInterval is not greater than zero, ignoring");
			return;
		}
		j->start_interval = value;
		if (-1 == kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, value, j))
			job_log_error(j, LOG_ERR, "adding kevent timer");
	}

}

void
job_import_dictionary(struct jobcb *j, const char *key, launch_data_t value)
{
	launch_data_t tmp;

	if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE) == 0) {
		launch_data_dict_iterate(value, semaphoreitem_setup, j);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_INETDCOMPATIBILITY) == 0) {
		j->inetcompat = true;
		if ((tmp = launch_data_dict_lookup(value, LAUNCH_JOBINETDCOMPATIBILITY_WAIT)))
			j->inetcompat_wait = launch_data_get_bool(tmp);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES) == 0) {
		launch_data_dict_iterate(value, envitem_setup, j);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES) == 0) {
		j->importing_global_env = true;
		launch_data_dict_iterate(value, envitem_setup, j);
		j->importing_global_env = false;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_SOFTRESOURCELIMITS) == 0) {
		launch_data_dict_iterate(value, limititem_setup, j);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_HARDRESOURCELIMITS) == 0) {
		j->importing_hard_limits = true;
		launch_data_dict_iterate(value, limititem_setup, j);
		j->importing_hard_limits = false;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_SOCKETS) == 0) {
		launch_data_dict_iterate(value, socketgroup_setup, j);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_MACHSERVICES) == 0) {
		launch_data_dict_iterate(value, machservice_setup, j);
		if (!SLIST_EMPTY(&j->machservices))
			job_setup_machport(j);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_STARTCALENDARINTERVAL) == 0) {
		calendarinterval_new_from_obj(j, value);
	}
}

void
job_import_array(struct jobcb *j, const char *key, launch_data_t value)
{
	bool is_q_dir = false;
	bool is_wp = false;

	if (strcasecmp(key, LAUNCH_JOBKEY_QUEUEDIRECTORIES) == 0) {
		is_q_dir = true;
		is_wp = true;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_WATCHPATHS) == 0) {
		is_wp = true;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_BONJOURFDS) == 0) {
		socketgroup_setup(value, LAUNCH_JOBKEY_BONJOURFDS, j);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_STARTCALENDARINTERVAL) == 0) {
		size_t i = 0, ci_cnt = launch_data_array_get_count(value);
		for (i = 0; i < ci_cnt; i++)
			calendarinterval_new_from_obj(j, launch_data_array_get_index(value, i));
	}

	if (is_wp) {
		size_t i, wp_cnt = launch_data_array_get_count(value);
		const char *thepath;
		for (i = 0; i < wp_cnt; i++) {
			thepath = launch_data_get_string(launch_data_array_get_index(value, i));
			watchpath_new(j, thepath, is_q_dir);
		}
	}
}

void
job_import_keys(launch_data_t obj, const char *key, void *context)
{
	struct jobcb *j = context;
	launch_data_type_t kind;

	if (obj == NULL)
		return;

	kind = launch_data_get_type(obj);

	switch (kind) {
	case LAUNCH_DATA_BOOL:
		job_import_bool(j, key, launch_data_get_bool(obj));
		break;
	case LAUNCH_DATA_STRING:
		job_import_string(j, key, launch_data_get_string(obj));
		break;
	case LAUNCH_DATA_INTEGER:
		job_import_integer(j, key, launch_data_get_integer(obj));
		break;
	case LAUNCH_DATA_DICTIONARY:
		job_import_dictionary(j, key, obj);
		break;
	case LAUNCH_DATA_ARRAY:
		job_import_array(j, key, obj);
		break;
	default:
		job_log(j, LOG_WARNING, "Unknown value type '%d' for key: %s", kind, key);
		break;
	}
}

struct jobcb *
job_import2(launch_data_t pload)
{
	launch_data_t tmp, ldpa;
	const char *label = NULL, *prog = NULL;
	const char **argv = NULL;
	struct jobcb *j;

	if (pload == NULL)
		return NULL;

	if (launch_data_get_type(pload) != LAUNCH_DATA_DICTIONARY)
		return NULL;

	if ((tmp = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_LABEL)) &&
			(launch_data_get_type(tmp) == LAUNCH_DATA_STRING)) {
		label = launch_data_get_string(tmp);
	}
	if ((tmp = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAM)) &&
			(launch_data_get_type(tmp) == LAUNCH_DATA_STRING)) {
		prog = launch_data_get_string(tmp);
	}
	ldpa = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAMARGUMENTS);

	if (label == NULL) {
		errno = EINVAL;
		return NULL;
	} else if ((j = job_find(label)) != NULL) {
		errno = EEXIST;
		return NULL;
	} else if ((strncasecmp(label, "com.apple.launchd", strlen("com.apple.launchd")) == 0) ||
			(strncasecmp(label, "via_mach_init", strlen("via_mach_init")) == 0)) {
		/* com.apple.launchd and via_mach_init prefixes for labels are reserved */
		errno = EINVAL;
		return NULL;
	}

	if (ldpa) {
		size_t i, c = launch_data_array_get_count(ldpa);

		argv = alloca((c + 1) * sizeof(char *));

		for (i = 0; i < c; i++)
			argv[i] = launch_data_get_string(launch_data_array_get_index(ldpa, i));
		argv[i] = NULL;
	}

	if ((j = job_new(root_bootstrap, label, prog, argv, NULL)))
		launch_data_dict_iterate(pload, job_import_keys, j);

	return j;
}

struct jobcb *
job_find2(struct bootstrap *b, const char *label)
{
	struct bootstrap *sbi;
	struct jobcb *ji;

	SLIST_FOREACH(ji, &b->jobs, sle) {
		if (strcmp(ji->label, label) == 0)
			return ji;
	}

	SLIST_FOREACH(sbi, &b->sub_bstraps, sle) {
		if ((ji = job_find2(sbi, label)))
			return ji;
	}

	errno = ESRCH;
	return NULL;
}

struct jobcb *
job_find(const char *label)
{
	return job_find2(root_bootstrap, label);
}

static void
job_export_all2(struct bootstrap *b, launch_data_t where)
{
	struct bootstrap *sbi;
	struct jobcb *ji;

	SLIST_FOREACH(ji, &b->jobs, sle) {
		launch_data_t tmp = job_export(ji);
		launch_data_dict_insert(where, tmp, ji->label);
	}

	SLIST_FOREACH(sbi, &b->sub_bstraps, sle)
		job_export_all2(sbi, where);
}

launch_data_t
job_export_all(void)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	job_export_all2(root_bootstrap, resp);

	return resp;
}

void
job_reap(struct jobcb *j)
{
	time_t td = time(NULL) - j->start_time;
	bool bad_exit = false;
	int status;

	job_log(j, LOG_DEBUG, "Reaping");

	if (j->execfd) {
		launchd_assumes(close(j->execfd) == 0);
		j->execfd = 0;
	}

#ifdef PID1_REAP_ADOPTED_CHILDREN
	if (getpid() == 1)
		status = pid1_child_exit_status;
	else
#endif
	if (-1 == waitpid(j->p, &status, 0)) {
		job_log_error(j, LOG_ERR, "waitpid(%d, ...)", j->p);
		return;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		job_log(j, LOG_WARNING, "exited with exit code: %d", WEXITSTATUS(status));
		bad_exit = true;
	}

	if (WIFSIGNALED(status)) {
		int s = WTERMSIG(status);
		if (SIGKILL == s || SIGTERM == s) {
			job_log(j, LOG_NOTICE, "exited: %s", strsignal(s));
		} else {
			job_log(j, LOG_WARNING, "exited abnormally: %s", strsignal(s));
			bad_exit = true;
		}
	}

	if (!j->ondemand && !j->legacy_mach_job) {
		if (td < LAUNCHD_MIN_JOB_RUN_TIME) {
			job_log(j, LOG_WARNING, "respawning too quickly! throttling");
			bad_exit = true;
			j->throttle = true;
		} else if (td >= LAUNCHD_REWARD_JOB_RUN_TIME) {
			job_log(j, LOG_INFO, "lived long enough, forgiving past exit failures");
			j->failed_exits = 0;
		}
	}

	if (!j->legacy_mach_job && bad_exit)
		j->failed_exits++;

	if (j->failed_exits > 0) {
		int failures_left = LAUNCHD_FAILED_EXITS_THRESHOLD - j->failed_exits;
		if (failures_left)
			job_log(j, LOG_WARNING, "%d more failure%s without living at least %d seconds will cause job removal",
					failures_left, failures_left > 1 ? "s" : "", LAUNCHD_REWARD_JOB_RUN_TIME);
	}

	total_children--;
	j->last_exit_status = status;
	j->p = 0;
}

void
job_dispatch(struct jobcb *j)
{
	if (job_active(j)) {
		return;
	} else if (job_useless(j)) {
		job_remove(j);
	} else if (job_keepalive(j)) {
		job_start(j);
	} else {
		job_watch(j);
	}
}

void
job_callback(void *obj, struct kevent *kev)
{
	struct jobcb *j = obj;
	bool d = j->debug;
	int oldmask = 0;

	current_rpc_server = obj;

	if (d) {
		oldmask = setlogmask(LOG_UPTO(LOG_DEBUG));
		job_log(j, LOG_DEBUG, "log level debug temporarily enabled while processing job");
	}

	switch (kev->filter) {
	case EVFILT_PROC:
		job_reap(j);

		if (j->firstborn) {
			job_log(j, LOG_DEBUG, "first born died, begin shutdown");
			launchd_shutdown();
		} else {
			job_dispatch(j);
		}
		break;
	case EVFILT_TIMER:
		calendarinterval_callback(j, kev);
		break;
	case EVFILT_VNODE:
		watchpath_callback(j, kev);
		break;
	case EVFILT_READ:
		if ((int)kev->ident != j->execfd) {
			socketgroup_callback(j, kev);
			break;
		}
		if (kev->data > 0) {
			int e;

			read(j->execfd, &e, sizeof(e));
			errno = e;
			job_log_error(j, LOG_ERR, "execve()");
			job_remove(j);
			j = NULL;
		} else {
			launchd_assumes(close(j->execfd) == 0);
			j->execfd = 0;
		}
		break;
	case EVFILT_MACHPORT:
		if (j->priv_port == kev->ident) {
			struct kevent newkev = *kev;
			newkev.udata = j->bstrap;
			bootstrap_callback(j->bstrap, &newkev);
		} else {
			job_start(j);
		}
		break;
	default:
		launchd_assumes(false);
		break;
	}

	if (d) {
		/* the job might have been removed, must not call job_log() */
		syslog(LOG_DEBUG, "restoring original log mask");
		setlogmask(oldmask);
	}

	current_rpc_server = NULL;
}

void
job_start(struct jobcb *j)
{
	mach_port_t which_bsport = j->bstrap->bootstrap_port;
	int spair[2];
	int execspair[2];
	char nbuf[64];
	pid_t c;
	bool sipc = false;

	if (job_active(j)) {
		job_log(j, LOG_DEBUG, "Already started");
		return;
	} else if (!j->legacy_mach_job && j->throttle) {
		j->throttle = false;
		job_log(j, LOG_WARNING, "Throttling: Will restart in %d seconds", LAUNCHD_MIN_JOB_RUN_TIME);
		launchd_assumes(kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_ADD|EV_ONESHOT,
					NOTE_SECONDS, LAUNCHD_MIN_JOB_RUN_TIME, j) != -1);
		return;
	}

	job_log(j, LOG_DEBUG, "Starting");

	if (!j->legacy_mach_job)
		sipc = (!SLIST_EMPTY(&j->sockets) || !SLIST_EMPTY(&j->machservices));

	/* FIXME, using stdinpath is a hack for re-reading the conf file */
	if (j->stdinpath)
	       sipc = true;

	j->checkedin = false;

	if (sipc)
		socketpair(AF_UNIX, SOCK_STREAM, 0, spair);

	socketpair(AF_UNIX, SOCK_STREAM, 0, execspair);

	time(&j->start_time);

	if (!SLIST_EMPTY(&j->machservices)) {
		launchd_assumes(launchd_mport_notify_req(j->priv_port, MACH_NOTIFY_NO_SENDERS) == KERN_SUCCESS);
		which_bsport = j->priv_port;
	}

	switch (c = fork_with_bootstrap_port(which_bsport)) {
	case -1:
		job_log_error(j, LOG_ERR, "fork() failed, will try again in one second");
		launchd_assumes(close(execspair[0]) == 0);
		launchd_assumes(close(execspair[1]) == 0);
		if (sipc) {
			launchd_assumes(close(spair[0]) == 0);
			launchd_assumes(close(spair[1]) == 0);
		}
		break;
	case 0:
		launchd_assumes(close(execspair[0]) == 0);
		/* wait for our parent to say they've attached a kevent to us */
		read(_fd(execspair[1]), &c, sizeof(c));
		if (j->firstborn) {
			setpgid(getpid(), getpid());
			if (isatty(STDIN_FILENO)) {
				if (tcsetpgrp(STDIN_FILENO, getpid()) == -1)
					job_log_error(j, LOG_WARNING, "tcsetpgrp()");
			}
		}

		if (sipc) {
			launchd_assumes(close(spair[0]) == 0);
			sprintf(nbuf, "%d", spair[1]);
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
		}
		job_start_child(j, execspair[1]);
		break;
	default:
		if (!SLIST_EMPTY(&j->machservices))
			j->priv_port_has_senders = true;
		j->p = c;
		total_children++;
		launchd_assumes(close(execspair[1]) == 0);
		j->execfd = _fd(execspair[0]);
		if (sipc) {
			launchd_assumes(close(spair[1]) == 0);
			ipc_open(_fd(spair[0]), j);
		}
		if (kevent_mod(j->execfd, EVFILT_READ, EV_ADD, 0, 0, &j->kqjob_callback) == -1)
			job_log_error(j, LOG_ERR, "kevent_mod(j->execfd): %m");
		if (kevent_mod(c, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &j->kqjob_callback) == -1) {
			job_log_error(j, LOG_ERR, "kevent()");
			job_reap(j);
		} else {
		       	if (j->ondemand)
				job_ignore(j);
		}
		/* this unblocks the child and avoids a race
		 * between the above fork() and the kevent_mod() */
		write(j->execfd, &c, sizeof(c));
		break;
	}
}

void
job_start_child(struct jobcb *j, int execfd)
{
	const char **argv, *file2exec = "/usr/libexec/launchproxy";
	int i, r;

	job_setup_attributes(j);

	if (j->argv) {
		argv = alloca((j->argc + 2) * sizeof(char *));
		for (i = 0; i < j->argc; i++)
			argv[i + 1] = j->argv[i];
		argv[i + 1] = NULL;
	} else {
		argv = alloca(3 * sizeof(char *));
		argv[1] = j->prog;
		argv[2] = NULL;
	}

	if (j->inetcompat) {
		argv[0] = file2exec;
	} else {
		argv++;
		file2exec = job_prog(j);
	}

	if (j->prog) {
		r = execv(file2exec, (char *const*)argv);
	} else {
		r = execvp(file2exec, (char *const*)argv);
	}

	if (-1 == r) {
		write(execfd, &errno, sizeof(errno));
		job_log_error(j, LOG_ERR, "execv%s(\"%s\", ...)", j->prog ? "" : "p", file2exec);
	}
	exit(EXIT_FAILURE);
}

void job_setup_env_from_other_jobs(struct bootstrap *b)
{
	struct bootstrap *sbi;
	struct envitem *ei;
	struct jobcb *ji;

	SLIST_FOREACH(sbi, &b->sub_bstraps, sle)
		job_setup_env_from_other_jobs(sbi);

	SLIST_FOREACH(ji, &b->jobs, sle) {
		SLIST_FOREACH(ei, &ji->global_env, sle)
			setenv(ei->key, ei->value, 1);
	}
}

void
job_setup_attributes(struct jobcb *j)
{
	struct limititem *li;
	struct envitem *ei;
	struct group *gre = NULL;
	gid_t gre_g = 0;

	setpriority(PRIO_PROCESS, 0, j->nice);

	SLIST_FOREACH(li, &j->limits, sle) {
		struct rlimit rl;

		if (getrlimit(li->which, &rl) == -1) {
			job_log_error(j, LOG_WARNING, "getrlimit()");
			continue;
		}

		if (li->sethard)
			rl.rlim_max = li->lim.rlim_max;
		if (li->setsoft)
			rl.rlim_cur = li->lim.rlim_cur;

		if (setrlimit(li->which, &rl) == -1)
			job_log_error(j, LOG_WARNING, "setrlimit()");
	}

	if (!j->inetcompat && j->session_create)
		launchd_SessionCreate();

	if (j->low_pri_io) {
		int lowprimib[] = { CTL_KERN, KERN_PROC_LOW_PRI_IO };
		int val = 1;

		if (sysctl(lowprimib, sizeof(lowprimib) / sizeof(lowprimib[0]), NULL, NULL,  &val, sizeof(val)) == -1)
			job_log_error(j, LOG_WARNING, "sysctl(\"%s\")", "kern.proc_low_pri_io");
	}
	if (j->rootdir) {
		chroot(j->rootdir);
		chdir(".");
	}
	if (j->groupname) {
		gre = getgrnam(j->groupname);
		if (gre) {
			gre_g = gre->gr_gid;
			if (-1 == setgid(gre_g)) {
				job_log_error(j, LOG_ERR, "setgid(%d)", gre_g);
				exit(EXIT_FAILURE);
			}
		} else {
			job_log(j, LOG_ERR, "getgrnam(\"%s\") failed", j->groupname);
			exit(EXIT_FAILURE);
		}
	}
	if (j->username || j->mach_uid) {
		struct passwd *pwe;

		if (j->username)
			pwe = getpwnam(j->username);
		else
			pwe = getpwuid(j->mach_uid);

		if (pwe) {
			uid_t pwe_u = pwe->pw_uid;
			uid_t pwe_g = pwe->pw_gid;

			if (pwe->pw_expire && time(NULL) >= pwe->pw_expire) {
				job_log(j, LOG_ERR, "expired account: %s", j->username);
				exit(EXIT_FAILURE);
			}
			if (j->init_groups) {
				if (-1 == initgroups(j->username, gre ? gre_g : pwe_g)) {
					job_log_error(j, LOG_ERR, "initgroups()");
					exit(EXIT_FAILURE);
				}
			}
			if (!gre) {
				if (-1 == setgid(pwe_g)) {
					job_log_error(j, LOG_ERR, "setgid(%d)", pwe_g);
					exit(EXIT_FAILURE);
				}
			}
			if (-1 == setuid(pwe_u)) {
				job_log_error(j, LOG_ERR, "setuid(%d)", pwe_u);
				exit(EXIT_FAILURE);
			}
		} else {
			job_log(j, LOG_WARNING, "getpwnam(\"%s\") failed", j->username);
			exit(EXIT_FAILURE);
		}
	}
	if (j->workingdir)
		chdir(j->workingdir);
	if (j->setmask) 
		umask(j->mask);
	if (j->stdinpath) {
		int sifd = open(j->stdinpath, O_RDONLY);
		if (sifd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", j->stdinpath);
		} else {
			launchd_assumes(dup2(sifd, STDIN_FILENO) != -1);
			launchd_assumes(close(sifd) == 0);
		}
	}
	if (j->stdoutpath) {
		int sofd = open(j->stdoutpath, O_WRONLY|O_APPEND|O_CREAT, DEFFILEMODE);
		if (sofd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", j->stdoutpath);
		} else {
			launchd_assumes(dup2(sofd, STDOUT_FILENO) != -1);
			launchd_assumes(close(sofd) == 0);
		}
	}
	if (j->stderrpath) {
		int sefd = open(j->stderrpath, O_WRONLY|O_APPEND|O_CREAT, DEFFILEMODE);
		if (sefd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", j->stderrpath);
		} else {
			launchd_assumes(dup2(sefd, STDERR_FILENO) != -1);
			launchd_assumes(close(sefd) == 0);
		}
	}

	job_setup_env_from_other_jobs(root_bootstrap);

	SLIST_FOREACH(ei, &j->env, sle)
		setenv(ei->key, ei->value, 1);

	setsid();
}

int
dir_has_files(const char *path)
{
	DIR *dd = opendir(path);
	struct dirent *de;
	bool r = 0;

	if (!dd)
		return -1;

	while ((de = readdir(dd))) {
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			r = 1;
			break;
		}
	}

	launchd_assumes(closedir(dd) == 0);
	return r;
}

void
calendarinterval_setalarm(struct jobcb *j, struct calendarinterval *ci)
{
	struct tm otherlatertm, latertm, *nowtm;
	time_t later, otherlater = 0, now = time(NULL);

	nowtm = localtime(&now);

	latertm = *nowtm;

	latertm.tm_sec = 0;
	latertm.tm_isdst = -1;


	if (-1 != ci->when.tm_min)
		latertm.tm_min = ci->when.tm_min;
	if (-1 != ci->when.tm_hour)
		latertm.tm_hour = ci->when.tm_hour;

	otherlatertm = latertm;

	if (-1 != ci->when.tm_mday)
		latertm.tm_mday = ci->when.tm_mday;
	if (-1 != ci->when.tm_mon)
		latertm.tm_mon = ci->when.tm_mon;

	/* cron semantics are fun */
	if (-1 != ci->when.tm_wday) {
		int delta, realwday = ci->when.tm_wday;

		if (realwday == 7)
			realwday = 0;
		
		delta = realwday - nowtm->tm_wday;
		
		/* Now Later Delta Desired
		 *   0     6     6       6
		 *   6     0    -6  7 + -6
		 *   1     5     4       4
		 *   5     1    -4  7 + -4
		 */
		if (delta > 0) {
			otherlatertm.tm_mday += delta;
		} else if (delta < 0) {
			otherlatertm.tm_mday += 7 + delta;
		} else if (-1 != ci->when.tm_hour && otherlatertm.tm_hour <= nowtm->tm_hour) {
			otherlatertm.tm_mday += 7;
		} else if (-1 != ci->when.tm_min && otherlatertm.tm_min <= nowtm->tm_min) {
			otherlatertm.tm_hour++;
		} else {
			otherlatertm.tm_min++;
		}

		otherlater = mktime(&otherlatertm);
	}

	if (-1 != ci->when.tm_mon && latertm.tm_mon <= nowtm->tm_mon) {
		latertm.tm_year++;
	} else if (-1 != ci->when.tm_mday && latertm.tm_mday <= nowtm->tm_mday) {
		latertm.tm_mon++;
	} else if (-1 != ci->when.tm_hour && latertm.tm_hour <= nowtm->tm_hour) {
		latertm.tm_mday++;
	} else if (-1 != ci->when.tm_min && latertm.tm_min <= nowtm->tm_min) {
		latertm.tm_hour++;
	} else {
		latertm.tm_min++;
	}

	later = mktime(&latertm);

	if (otherlater) {
		if (-1 != ci->when.tm_mday)
			later = later < otherlater ? later : otherlater;
		else
			later = otherlater;
	}

	if (-1 == kevent_mod((uintptr_t)ci, EVFILT_TIMER, EV_ADD, NOTE_ABSOLUTE|NOTE_SECONDS, later, j)) {
		job_log_error(j, LOG_ERR, "adding kevent alarm");
	} else {
		job_log(j, LOG_INFO, "scheduled to run again at %s", ctime(&later));
	}
}

void
job_log_error(struct jobcb *j, int pri, const char *msg, ...)
{
	size_t newmsg_sz = strlen(msg) + strlen(j->label) + 200;
	char *newmsg = alloca(newmsg_sz);
	va_list ap;

	sprintf(newmsg, "%s: %s: %s", j->label, msg, strerror(errno));

	va_start(ap, msg);

	vsyslog(pri, newmsg, ap);

	va_end(ap);
}

void
job_log(struct jobcb *j, int pri, const char *msg, ...)
{
	size_t newmsg_sz = strlen(msg) + sizeof(": ") + strlen(j->label);
	char *newmsg = alloca(newmsg_sz);
	va_list ap;

	sprintf(newmsg, "%s: %s", j->label, msg);

	va_start(ap, msg);

	vsyslog(pri, newmsg, ap);

	va_end(ap);
}

bool
watchpath_new(struct jobcb *j, const char *name, bool qdir)
{
	struct watchpath *wp = calloc(1, sizeof(struct watchpath) + strlen(name) + 1);

	if (!launchd_assumes(wp != NULL))
		return false;

	wp->is_qdir = qdir;

	wp->fd = -1; /* watchpath_watch() will open this */

	strcpy(wp->name, name);

	SLIST_INSERT_HEAD(&j->vnodes, wp, sle);

	return true;
}       

void
watchpath_delete(struct jobcb *j, struct watchpath *wp) 
{
	if (wp->fd != -1)
		launchd_assumes(close(wp->fd) != -1);

	SLIST_REMOVE(&j->vnodes, wp, watchpath, sle);

	free(wp);
}       

void    
watchpath_ignore(struct jobcb *j, struct watchpath *wp)
{       
	if (wp->fd != -1) {
		job_log(j, LOG_DEBUG, "Ignoring Vnode: %d", wp->fd);
		launchd_assumes(kevent_mod(wp->fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL) != -1);
	}
}

void
watchpath_watch(struct jobcb *j, struct watchpath *wp)
{
	int fflags = NOTE_WRITE|NOTE_EXTEND|NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE|NOTE_ATTRIB|NOTE_LINK;
	int qdir_file_cnt;

	if (wp->is_qdir)
		fflags = NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_LINK;

	if (wp->fd == -1)
		wp->fd = _fd(open(wp->name, O_EVTONLY));

	if (wp->fd == -1)
		return job_log_error(j, LOG_ERR, "open(\"%s\", O_EVTONLY)", wp->name);

	job_log(j, LOG_DEBUG, "Watching Vnode: %d", wp->fd);
	launchd_assumes(kevent_mod(wp->fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, fflags, 0, j) != -1);

	if (!wp->is_qdir)
		return;

	if (-1 == (qdir_file_cnt = dir_has_files(wp->name))) {
		job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", wp->name);
	} else if (qdir_file_cnt > 0) {
		job_start(j);
	}
}

void
watchpath_callback(struct jobcb *j, struct kevent *kev)
{
	struct watchpath *wp;
	int dir_file_cnt;

	SLIST_FOREACH(wp, &j->vnodes, sle) {
		if (wp->fd == (int)kev->ident)
			break;
	}

	launchd_assumes(wp != NULL);

	if ((NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE) & kev->fflags) {
		job_log(j, LOG_DEBUG, "Path invalidated: %s", wp->name);
		launchd_assumes(close(wp->fd) == 0);
		wp->fd = -1; /* this will get fixed in watchpath_watch() */
	} else if (!wp->is_qdir) {
		job_log(j, LOG_DEBUG, "Watch path modified: %s", wp->name);
	} else {
		job_log(j, LOG_DEBUG, "Queue directory modified: %s", wp->name);

		if (-1 == (dir_file_cnt = dir_has_files(wp->name))) {
			job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", wp->name);
		} else if (0 == dir_file_cnt) {
			job_log(j, LOG_DEBUG, "Spurious wake up, directory is empty again: %s", wp->name);
			return;
		}
	}

	job_start(j);
}

bool
calendarinterval_new_from_obj(struct jobcb *j, launch_data_t obj)
{
	launch_data_t tmp_k;
	struct tm tmptm;

	memset(&tmptm, 0, sizeof(0));

	tmptm.tm_min = -1;
	tmptm.tm_hour = -1;
	tmptm.tm_mday = -1;
	tmptm.tm_wday = -1;
	tmptm.tm_mon = -1;

	if (LAUNCH_DATA_DICTIONARY != launch_data_get_type(obj))
		return false;

	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_MINUTE)))
		tmptm.tm_min = launch_data_get_integer(tmp_k);
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_HOUR)))
		tmptm.tm_hour = launch_data_get_integer(tmp_k);
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_DAY)))
		tmptm.tm_mday = launch_data_get_integer(tmp_k);
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_WEEKDAY)))
		tmptm.tm_wday = launch_data_get_integer(tmp_k);
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_MONTH)))
		tmptm.tm_mon = launch_data_get_integer(tmp_k);

	return calendarinterval_new(j, &tmptm);
}

bool
calendarinterval_new(struct jobcb *j, struct tm *w)
{
	struct calendarinterval *ci = calloc(1, sizeof(struct calendarinterval));

	if (!launchd_assumes(ci != NULL))
		return false;

	ci->when = *w;

	SLIST_INSERT_HEAD(&j->cal_intervals, ci, sle);

	calendarinterval_setalarm(j, ci);

	return true;
}

void
calendarinterval_delete(struct jobcb *j, struct calendarinterval *ci)
{
	launchd_assumes(kevent_mod((uintptr_t)ci, EVFILT_TIMER, EV_DELETE, 0, 0, NULL) != -1);

	SLIST_REMOVE(&j->cal_intervals, ci, calendarinterval, sle);

	free(ci);
}

void
calendarinterval_callback(struct jobcb *j, struct kevent *kev)
{
	struct calendarinterval *ci;

	SLIST_FOREACH(ci, &j->cal_intervals, sle) {
		if ((uintptr_t)ci == kev->ident)
			break;
	}

	if (ci != NULL)
		calendarinterval_setalarm(j, ci);

	job_start(j);
}

bool
socketgroup_new(struct jobcb *j, const char *name, int *fds, unsigned int fd_cnt, bool junkfds)
{
	struct socketgroup *sg = calloc(1, sizeof(struct socketgroup) + strlen(name) + 1);

	if (!launchd_assumes(sg != NULL))
		return false;

	sg->fds = calloc(1, fd_cnt * sizeof(int));
	sg->fd_cnt = fd_cnt;
	sg->junkfds = junkfds;

	if (!launchd_assumes(sg->fds != NULL)) {
		free(sg);
		return false;
	}

	memcpy(sg->fds, fds, fd_cnt * sizeof(int));
	strcpy(sg->name, name);

	SLIST_INSERT_HEAD(&j->sockets, sg, sle);

	return true;
}

void
socketgroup_delete(struct jobcb *j, struct socketgroup *sg)
{
	unsigned int i;

	for (i = 0; i < sg->fd_cnt; i++)
		launchd_assumes(close(sg->fds[i]) != -1);

	SLIST_REMOVE(&j->sockets, sg, socketgroup, sle);

	free(sg->fds);
	free(sg);
}

void
socketgroup_ignore(struct jobcb *j, struct socketgroup *sg)
{
	char buf[10000];
	unsigned int i, buf_off = 0;

	if (sg->junkfds)
		return;

	for (i = 0; i < sg->fd_cnt; i++)
		buf_off += sprintf(buf + buf_off, " %d", sg->fds[i]);

	job_log(j, LOG_DEBUG, "Ignoring Sockets:%s", buf);

	for (i = 0; i < sg->fd_cnt; i++)
		launchd_assumes(kevent_mod(sg->fds[i], EVFILT_READ, EV_DELETE, 0, 0, NULL) != -1);
}

void
socketgroup_watch(struct jobcb *j, struct socketgroup *sg)
{
	char buf[10000];
	unsigned int i, buf_off = 0;

	if (sg->junkfds)
		return;

	for (i = 0; i < sg->fd_cnt; i++)
		buf_off += sprintf(buf + buf_off, " %d", sg->fds[i]);

	job_log(j, LOG_DEBUG, "Watching sockets:%s", buf);

	for (i = 0; i < sg->fd_cnt; i++)
		launchd_assumes(kevent_mod(sg->fds[i], EVFILT_READ, EV_ADD, 0, 0, j) != -1);
}

void
socketgroup_callback(struct jobcb *j, struct kevent *kev)
{
	job_start(j);
}

bool
envitem_new(struct jobcb *j, const char *k, const char *v, bool global)
{
	struct envitem *ei = calloc(1, sizeof(struct envitem) + strlen(k) + 1 + strlen(v) + 1);

	if (!launchd_assumes(ei != NULL))
		return false;

	strcpy(ei->key, k);
	ei->value = ei->key + strlen(v) + 1;
	strcpy(ei->value, v);

	if (global) {
		SLIST_INSERT_HEAD(&j->global_env, ei, sle);
	} else {
		SLIST_INSERT_HEAD(&j->env, ei, sle);
	}

	return true;
}

void
envitem_delete(struct jobcb *j, struct envitem *ei, bool global)
{
	if (global) {
		SLIST_REMOVE(&j->global_env, ei, envitem, sle);
	} else {
		SLIST_REMOVE(&j->env, ei, envitem, sle);
	}

	free(ei);
}

void
envitem_setup(launch_data_t obj, const char *key, void *context)
{
	struct jobcb *j = context;

	if (launch_data_get_type(obj) != LAUNCH_DATA_STRING)
		return;

	envitem_new(j, key, launch_data_get_string(obj), j->importing_global_env);
}

bool
limititem_update(struct jobcb *j, int w, rlim_t r)
{
	struct limititem *li;

	SLIST_FOREACH(li, &j->limits, sle) {
		if (li->which == w)
			break;
	}

	if (li == NULL) {
		li = calloc(1, sizeof(struct limititem));

		if (!launchd_assumes(li != NULL))
			return false;

		li->which = w;
	}

	if (j->importing_hard_limits) {
		li->lim.rlim_max = r;
		li->sethard = true;
	} else {
		li->lim.rlim_cur = r;
		li->setsoft = true;
	}

	return true;
}

void
limititem_delete(struct jobcb *j, struct limititem *li)
{
	SLIST_REMOVE(&j->limits, li, limititem, sle);

	free(li);
}

void
limititem_setup(launch_data_t obj, const char *key, void *context)
{
	struct jobcb *j = context;
	int i, limits_cnt = (sizeof(launchd_keys2limits) / sizeof(launchd_keys2limits[0]));
	rlim_t rl;

	if (launch_data_get_type(obj) != LAUNCH_DATA_INTEGER)
		return;

	rl = launch_data_get_integer(obj);

	for (i = 0; i < limits_cnt; i++) {
		if (strcasecmp(launchd_keys2limits[i].key, key) == 0)
			break;
	}

	if (i == limits_cnt)
		return;

	limititem_update(j, launchd_keys2limits[i].val, rl);
}

struct bootstrap *root_bootstrap = NULL;
struct bootstrap *ws_bootstrap = NULL;
struct bootstrap *current_rpc_bootstrap = NULL;
struct jobcb *current_rpc_server = NULL;

bool
job_useless(struct jobcb *j)
{
	if (shutdown_in_progress) {
		job_log(j, LOG_INFO, "Exited while shutdown in progress.");
		return true;
	} else if (j->failed_exits >= LAUNCHD_FAILED_EXITS_THRESHOLD) {
		job_log(j, LOG_WARNING, "too many failures in succession");
		return true;
	} else if (!j->checkedin && (!SLIST_EMPTY(&j->sockets) || !SLIST_EMPTY(&j->machservices))) {
		job_log(j, LOG_WARNING, "Failed to check-in!");
		return true;
	} else if (j->legacy_mach_job && SLIST_EMPTY(&j->machservices)) {
		job_log(j, LOG_INFO, "Garbage collecting");
		return true;
	}

	return false;
}

bool
job_ondemand(struct jobcb *j)
{
	return j->ondemand;
}

bool
job_keepalive(struct jobcb *j)
{
	struct semaphoreitem *si;
	struct stat sb;
	bool dispatch_others = false;
	bool good_exit = (WIFEXITED(j->last_exit_status) && WEXITSTATUS(j->last_exit_status) == 0);

	if (j->runatload && j->start_time == 0)
		return true;

	if (!j->ondemand)
		return true;

	if (SLIST_EMPTY(&j->semaphores))
		return false;

	SLIST_FOREACH(si, &j->semaphores, sle) {
		switch (si->why) {
		case NETWORK_UP:
			if (network_up) return true;
			break;
		case NETWORK_DOWN:
			if (!network_up) return true;
			break;
		case SUCCESSFUL_EXIT:
			if (good_exit) return true;
			break;
		case FAILED_EXIT:
			if (!good_exit) return true;
			break;
		case PATH_EXISTS:
			if (stat(si->what, &sb) == 0) return true;
			dispatch_others = true;
			break;
		case PATH_MISSING:
			if (stat(si->what, &sb) == -1 && errno == ENOENT) return true;
			dispatch_others = true;
			break;
		}
	}

	/* Maybe another job has the inverse path based semaphore as this job */
	if (dispatch_others)
		job_dispatch_all_other_semaphores(j, root_bootstrap);

	return false;
}

const char *
job_prog(struct jobcb *j)
{
	if (j->prog) {
		return j->prog;
	} else {
		return j->argv[0];
	}
}

bool
job_active(struct jobcb *j)
{
	struct machservice *servicep;

	if (j->p)
		return true;

	if (j->priv_port_has_senders) {
		if (j->start_time && !j->checkedin) {
			if (j->legacy_mach_job) {
				job_log(j, LOG_NOTICE, "Daemonized. Extremely expensive no-op.");
			} else {
				job_log(j, LOG_ERR, "Daemonization is not supported under launchd.");
				return false;
			}
		}
		return true;
	}

	SLIST_FOREACH(servicep, &j->machservices, sle) {
		if (servicep->isActive)
			return true;
	}

	return false;
}

pid_t launchd_fork(void)
{
	return fork_with_bootstrap_port(root_bootstrap->bootstrap_port);
}

pid_t launchd_ws_fork(void)
{
	return fork_with_bootstrap_port(ws_bootstrap->bootstrap_port);
}

pid_t
fork_with_bootstrap_port(mach_port_t p)
{
	pid_t r = -1;

	sigprocmask(SIG_BLOCK, &blocked_signals, NULL);

	launchd_assumes(launchd_mport_make_send(p) == KERN_SUCCESS);
	launchd_assumes(launchd_set_bport(p) == KERN_SUCCESS);
	launchd_assumes(launchd_mport_deallocate(p) == KERN_SUCCESS);

	r = fork();

	if (r != 0) {
		launchd_assumes(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);
	} else if (r == 0) {
		size_t i;

		for (i = 0; i <= NSIG; i++) {
			if (sigismember(&blocked_signals, i))
				signal(i, SIG_DFL);
		}
	}

	sigprocmask(SIG_UNBLOCK, &blocked_signals, NULL);
	
	return r;
}

void
machservice_resetport(struct jobcb *j, struct machservice *ms)
{
	launchd_assumes(launchd_mport_close_recv(ms->port) == KERN_SUCCESS);
	launchd_assumes(launchd_mport_deallocate(ms->port) == KERN_SUCCESS);
	launchd_assumes(launchd_mport_create_recv(&ms->port, j) == KERN_SUCCESS);
	launchd_assumes(launchd_mport_make_send(ms->port) == KERN_SUCCESS);
}

struct machservice *
machservice_new(struct bootstrap *bootstrap, const char *name, mach_port_t *serviceport, struct jobcb *j)
{
	struct machservice *servicep;

	if ((servicep = calloc(1, sizeof(struct machservice) + strlen(name) + 1)) == NULL)
		return NULL;

	if (j) {
		if (!launchd_assumes(launchd_mport_create_recv(&servicep->port, j) == KERN_SUCCESS))
			goto out_bad;

		if (!launchd_assumes(launchd_mport_make_send(servicep->port) == KERN_SUCCESS))
			goto out_bad2;
		*serviceport = servicep->port;
		servicep->isActive = false;
	} else {
		servicep->port = *serviceport;
		servicep->isActive = true;
	}

	if (j == ANY_JOB || j == NULL) {
		SLIST_INSERT_HEAD(&bootstrap->services, servicep, sle);
	} else {
		SLIST_INSERT_HEAD(&j->machservices, servicep, sle);
		servicep->job = j;
	}
	
	strcpy(servicep->name, name);
	servicep->bootstrap = bootstrap;

	syslog(LOG_INFO, "Created new service %x in bootstrap %x: %s", servicep->port, bootstrap->bootstrap_port, name);
	return servicep;
out_bad2:
	launchd_assumes(launchd_mport_close_recv(servicep->port) == KERN_SUCCESS);
out_bad:
	free(servicep);
	return NULL;
}

void
machservice_setup(launch_data_t obj, const char *key, void *context)
{
	struct jobcb *j = context;
	struct machservice *ms;
	mach_port_t p;
	bool reset = false;

	if (launch_data_get_type(obj) == LAUNCH_DATA_BOOL)
		reset = !launch_data_get_bool(obj);

	if (bootstrap_lookup_service(j->bstrap, key, false) == NULL) {
		ms = machservice_new(j->bstrap, key, &p, j);
		if (ms) {
			ms->isActive = false;
			ms->reset = reset;
		}
	}
}

/*
 * server_loop -- pick requests off our service port and process them
 * Also handles notifications
 */
union bootstrapMaxRequestSize {
	union __RequestUnion__x_bootstrap_subsystem req;
	union __ReplyUnion__x_bootstrap_subsystem rep;
};

void
bootstrap_callback(void *obj, struct kevent *kev)
{
	mach_msg_return_t mresult;

	current_rpc_bootstrap = obj;

	mresult = mach_msg_server_once(launchd_mach_ipc_demux, sizeof(union bootstrapMaxRequestSize), kev->ident,
			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SENDER)|MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
	if (!launchd_assumes(mresult == MACH_MSG_SUCCESS))
		syslog(LOG_ERR, "mach_msg_server_once(): %s", mach_error_string(mresult));

	current_rpc_bootstrap = NULL;
}

mach_port_t
bootstrap_rport(struct bootstrap *b)
{
	return b->bootstrap_port;
}

struct bootstrap *
bootstrap_rparent(struct bootstrap *b)
{
	return b->parent;
}

void
bootstrap_foreach_service(struct bootstrap *b, void (*bs_iter)(struct machservice *, void *), void *context)
{
	struct machservice *ms;
	struct jobcb *ji;

	SLIST_FOREACH(ji, &b->jobs, sle) {
		SLIST_FOREACH(ms, &ji->machservices, sle)
			bs_iter(ms, context);
	}

	SLIST_FOREACH(ms, &b->services, sle)
		bs_iter(ms, context);
}

struct bootstrap *
bootstrap_new(struct bootstrap *parent, mach_port_t requestorport)
{
	struct bootstrap *bootstrap;

	if ((bootstrap = calloc(1, sizeof(struct bootstrap))) == NULL)
		goto out_bad;

	bootstrap->kqbstrap_callback = bootstrap_callback;

	SLIST_INIT(&bootstrap->sub_bstraps);
	SLIST_INIT(&bootstrap->jobs);
	SLIST_INIT(&bootstrap->services);

	if (!launchd_assumes(launchd_mport_create_recv(&bootstrap->bootstrap_port, bootstrap) == KERN_SUCCESS))
		goto out_bad;

	if (!launchd_assumes(launchd_mport_watch(bootstrap->bootstrap_port) == KERN_SUCCESS))
		goto out_bad;

	if (requestorport != MACH_PORT_NULL) {
		bootstrap->requestor_port = requestorport;
		if (!launchd_assumes(launchd_mport_notify_req(requestorport, MACH_NOTIFY_DEAD_NAME) == KERN_SUCCESS))
			goto out_bad;
	}
	

	if (parent) {
		SLIST_INSERT_HEAD(&parent->sub_bstraps, bootstrap, sle);
		bootstrap->parent = parent;
	}

	return bootstrap;

out_bad:
	if (bootstrap) {
		if (bootstrap->bootstrap_port != MACH_PORT_NULL)
			launchd_assumes(launchd_mport_deallocate(bootstrap->bootstrap_port) == KERN_SUCCESS);
		free(bootstrap);
	}
	return NULL;
}

void
bootstrap_delete_anything_with_port(struct bootstrap *bootstrap, mach_port_t port)
{
	struct bootstrap *sub_bstrap, *next_bstrap;
	struct machservice *servicep, *next_servicep;
	struct jobcb *ji, *jn;

	/* Mach ports, unlike Unix descriptors, are reference counted. In other
	 * words, when some program hands us a second or subsequent send right
	 * to a port we already have open, the Mach kernel gives us the same
	 * port number back and increments an reference count associated with
	 * the port. This forces us, when discovering that a receive right at
	 * the other end has been deleted, to wander all of our objects to see
	 * what weird places clients might have handed us the same send right
	 * to use.
	 */

	if (bootstrap->requestor_port == port)
		return bootstrap_delete(bootstrap);

	SLIST_FOREACH_SAFE(sub_bstrap, &bootstrap->sub_bstraps, sle, next_bstrap)
		bootstrap_delete_anything_with_port(sub_bstrap, port);

	/* My naive intuition about Mach port semantics and their implications
	 * on our data structures says that we should never need to walk the
	 * server list in this function. Why? Because if the server dies, we
	 * get the port back in a backup notification. We'd never want to
	 * delete it unless the server consciously unregisters the service.
	 * Oh well, let's use launchd_assumes() to find out if we're wrong.
	 */
	SLIST_FOREACH_SAFE(ji, &bootstrap->jobs, sle, jn) {
		SLIST_FOREACH_SAFE(servicep, &ji->machservices, sle, next_servicep) {
			if (!launchd_assumes(servicep->port != port))
				machservice_delete(servicep);
		}
	}

	SLIST_FOREACH_SAFE(servicep, &bootstrap->services, sle, next_servicep) {
		if (servicep->port == port)
			machservice_delete(servicep);
	}
}

struct machservice *
bootstrap_lookup_service(struct bootstrap *bootstrap, const char *name, bool check_parent)
{
	struct machservice *ms;
	struct jobcb *ji;

	SLIST_FOREACH(ji, &bootstrap->jobs, sle) {
		SLIST_FOREACH(ms, &ji->machservices, sle) {
			if (strcmp(name, ms->name) == 0)
				return ms;
		}
	}

	SLIST_FOREACH(ms, &bootstrap->services, sle) {
		if (strcmp(name, ms->name) == 0)
				return ms;
	}

	if (bootstrap->parent == NULL)
		return NULL;

	if (!check_parent)
		return NULL;

	return bootstrap_lookup_service(bootstrap->parent, name, true);
}

mach_port_t
machservice_port(struct machservice *ms)
{
	return ms->port;
}

struct jobcb *
machservice_job(struct machservice *ms)
{
	return ms->job;
}

bool
machservice_active(struct machservice *ms)
{
	return ms->isActive;
}

const char *
machservice_name(struct machservice *ms)
{
	return ms->name;
}

struct bootstrap *
machservice_bootstrap(struct machservice *ms)
{
	return ms->bootstrap;
}

void
machservice_delete(struct machservice *servicep)
{
	if (servicep->job) {
		SLIST_REMOVE(&servicep->job->machservices, servicep, machservice, sle);
		syslog(LOG_INFO, "Declared service %s now unavailable", servicep->name);
		launchd_assumes(launchd_mport_close_recv(servicep->port) == KERN_SUCCESS);
	} else {
		SLIST_REMOVE(&servicep->bootstrap->services, servicep, machservice, sle);
		syslog(LOG_INFO, "Registered service %s deleted", servicep->name);
	}

	launchd_assumes(launchd_mport_deallocate(servicep->port) == KERN_SUCCESS);

	free(servicep);
}

void
machservice_watch(struct machservice *servicep)
{
	mach_msg_id_t which = MACH_NOTIFY_DEAD_NAME;

	servicep->isActive = true;

	if (servicep->job) {
		which = MACH_NOTIFY_PORT_DESTROYED;
		job_checkin(servicep->job);
	}

	launchd_assumes(launchd_mport_notify_req(servicep->port, which) == KERN_SUCCESS);
}

void
bootstrap_delete(struct bootstrap *bootstrap)
{
	struct bootstrap *sub_bstrap;
	struct machservice *servicep;
	struct jobcb *ji;

	if (!launchd_assumes(bootstrap != root_bootstrap))
		return;
	if (!launchd_assumes(bootstrap != ws_bootstrap))
		return;

	syslog(LOG_DEBUG, "Deleting bootstrap port: %x", bootstrap->bootstrap_port);

	while ((sub_bstrap = SLIST_FIRST(&bootstrap->sub_bstraps)))
		bootstrap_delete(sub_bstrap);

	while ((ji = SLIST_FIRST(&bootstrap->jobs)))
		job_remove(ji);

	while ((servicep = SLIST_FIRST(&bootstrap->services)))
		machservice_delete(servicep);

	if (bootstrap->requestor_port != MACH_PORT_NULL)
		launchd_assumes(launchd_mport_deallocate(bootstrap->requestor_port) == KERN_SUCCESS);

	launchd_assumes(launchd_mport_close_recv(bootstrap->bootstrap_port) == KERN_SUCCESS);

	if (bootstrap->parent)
		SLIST_REMOVE(&bootstrap->parent->sub_bstraps, bootstrap, bootstrap, sle);

	free(bootstrap);
}

#ifdef PID1_REAP_ADOPTED_CHILDREN

static bool job_reap_pid_with_bs(struct bootstrap *bootstrap, pid_t p);

bool job_reap_pid_with_bs(struct bootstrap *bootstrap, pid_t p)
{
	struct bootstrap *sub_bstrap;
	struct jobcb *ji;
	struct kevent kev;

	SLIST_FOREACH(ji, &bootstrap->jobs, sle) {
		if (ji->p == p) {
			EV_SET(&kev, p, EVFILT_PROC, 0, 0, 0, ji);
			ji->kqjob_callback(ji, &kev);
			return true;
		}
	}

	SLIST_FOREACH(sub_bstrap, &bootstrap->sub_bstraps, sle) {
		if (job_reap_pid_with_bs(sub_bstrap, p))
			return true;
	}

	return false;
}

bool job_reap_pid(pid_t p)
{
	return job_reap_pid_with_bs(root_bootstrap, p);
}
#endif

#define NELEM(x)                (sizeof(x)/sizeof(x[0]))
#define END_OF(x)               (&(x)[NELEM(x)])

char **
mach_cmd2argv(const char *string)
{
	char *argv[100], args[1000];
	const char *cp;
	char *argp = args, term, **argv_ret, *co;
	unsigned int nargs = 0, i;

	for (cp = string; *cp;) {
		while (isspace(*cp))
			cp++;
		term = (*cp == '"') ? *cp++ : '\0';
		if (nargs < NELEM(argv))
			argv[nargs++] = argp;
		while (*cp && (term ? *cp != term : !isspace(*cp)) && argp < END_OF(args)) {
			if (*cp == '\\')
				cp++;
			*argp++ = *cp;
			if (*cp)
				cp++;
		}
		*argp++ = '\0';
	}
	argv[nargs] = NULL;

	if (nargs == 0)
		return NULL;

	argv_ret = malloc((nargs + 1) * sizeof(char *) + strlen(string) + 1);

	if (!launchd_assumes(argv_ret != NULL))
		return NULL;

	co = (char *)argv_ret + (nargs + 1) * sizeof(char *);

	for (i = 0; i < nargs; i++) {
		strcpy(co, argv[i]);
		argv_ret[i] = co;
		co += strlen(argv[i]) + 1;
	}
	argv_ret[i] = NULL;
	
	return argv_ret;
}

void
job_checkin(struct jobcb *j)
{
	j->checkedin = true;
}

void
job_ack_port_destruction(struct jobcb *j, mach_port_t p)
{
	struct machservice *ms;

	SLIST_FOREACH(ms, &j->machservices, sle) {
		if (ms->port == p)
			break;
	}

	if (!launchd_assumes(ms != NULL))
		return;

	ms->isActive = false;

	if (ms->reset)
		machservice_resetport(j, ms);

	job_log(j, LOG_DEBUG, "Receive right returned to us: %s", ms->name);

	job_dispatch(j);
}

void
job_ack_no_senders(struct jobcb *j)
{
	j->priv_port_has_senders = false;

	job_log(j, LOG_DEBUG, "No more senders on privileged Mach bootstrap port");

	job_dispatch(j);
}

mach_port_t
job_get_priv_port(struct jobcb *j)
{
	return j->priv_port;
}


bool
semaphoreitem_new(struct jobcb *j, semaphore_reason_t why, const char *what)
{
	struct semaphoreitem *si;
	size_t alloc_sz = sizeof(struct semaphoreitem);

	if (what)
		alloc_sz += strlen(what) + 1;

	if (!launchd_assumes(si = calloc(1, alloc_sz)))
		return false;

	si->why = why;

	if (what)
		strcpy(si->what, what);

	SLIST_INSERT_HEAD(&j->semaphores, si, sle);

	return true;
}

void
semaphoreitem_delete(struct jobcb *j, struct semaphoreitem *ri)
{
	SLIST_REMOVE(&j->semaphores, ri, semaphoreitem, sle);

	free(ri);
}

void
semaphoreitem_setup_paths(launch_data_t obj, const char *key, void *context)
{
	struct jobcb *j = context;
	semaphore_reason_t why;

	why = launch_data_get_bool(obj) ? PATH_EXISTS : PATH_MISSING;

	semaphoreitem_new(j, why, key);
}

void
semaphoreitem_setup(launch_data_t obj, const char *key, void *context)
{
	struct jobcb *j = context;
	semaphore_reason_t why;

	if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_NETWORKSTATE) == 0) {
		why = launch_data_get_bool(obj) ? NETWORK_UP : NETWORK_DOWN;
		semaphoreitem_new(j, why, NULL);
	} else if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_SUCCESSFULEXIT) == 0) {
		why = launch_data_get_bool(obj) ? SUCCESSFUL_EXIT : FAILED_EXIT;
		semaphoreitem_new(j, why, NULL);
		j->runatload = true;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_PATHSTATE) == 0 &&
			launch_data_get_type(obj) == LAUNCH_DATA_DICTIONARY) {
		launch_data_dict_iterate(obj, semaphoreitem_setup_paths, j);
	}
}

void
job_dispatch_all_other_semaphores(struct jobcb *j, struct bootstrap *b)
{
	struct bootstrap *sbi;
	struct jobcb *ji;

	SLIST_FOREACH(sbi, &b->sub_bstraps, sle)
		job_dispatch_all_other_semaphores(j, sbi);

	SLIST_FOREACH(ji, &b->jobs, sle) {
		if (!SLIST_EMPTY(&ji->semaphores)) {
			if (j != ji)
				job_dispatch(ji);
		}
	}
}
