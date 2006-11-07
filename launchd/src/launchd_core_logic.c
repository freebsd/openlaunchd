/*
 * @APPLE_APACHE_LICENSE_HEADER_START@
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

static const char *const __rcs_file_version__ = "$Revision$";

#include "config.h"
#include "launchd_core_logic.h"

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/boolean.h>
#include <mach/message.h>
#include <mach/notify.h>
#include <mach/mig_errors.h>
#include <mach/mach_traps.h>
#include <mach/mach_interface.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/exception.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/ptrace.h>
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
#include <bsm/libbsm.h>
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
#include <glob.h>

#include "liblaunch_public.h"
#include "liblaunch_private.h"
#include "libbootstrap_public.h"
#include "libvproc_internal.h"

#include "launchd.h"
#include "launchd_runtime.h"
#include "launchd_unix_ipc.h"
#include "protocol_vproc.h"
#include "protocol_vprocServer.h"
#include "job_reply.h"

#define LAUNCHD_MIN_JOB_RUN_TIME 10
#define LAUNCHD_ADVISABLE_IDLE_TIMEOUT 30

static au_asid_t inherited_asid;
mach_port_t inherited_bootstrap_port;

static bool trusted_client_check(job_t j, struct ldcred *ldc);


struct machservice {
	SLIST_ENTRY(machservice) sle;
	job_t			job;
	mach_port_name_t	port;
	unsigned int		isActive:1, reset:1, recv:1, hide:1, kUNCServer:1, must_match_uid:1;
	char			name[0];
};

static void machservice_setup(launch_data_t obj, const char *key, void *context);
static void machservice_setup_options(launch_data_t obj, const char *key, void *context);
static void machservice_resetport(job_t j, struct machservice *ms);
static struct machservice *machservice_new(job_t j, const char *name, mach_port_t *serviceport);
static void machservice_delete(struct machservice *);
static void machservice_watch(struct machservice *);
static mach_port_t machservice_port(struct machservice *);
static job_t machservice_job(struct machservice *);
static bool machservice_hidden(struct machservice *);
static bool machservice_active(struct machservice *);
static const char *machservice_name(struct machservice *);
static bootstrap_status_t machservice_status(struct machservice *);

struct socketgroup {
	SLIST_ENTRY(socketgroup) sle;
	int *fds;
	unsigned int junkfds:1, fd_cnt:31;
	char name[0];
};

static bool socketgroup_new(job_t j, const char *name, int *fds, unsigned int fd_cnt, bool junkfds);
static void socketgroup_delete(job_t j, struct socketgroup *sg);
static void socketgroup_watch(job_t j, struct socketgroup *sg);
static void socketgroup_ignore(job_t j, struct socketgroup *sg);
static void socketgroup_callback(job_t j, struct kevent *kev);
static void socketgroup_setup(launch_data_t obj, const char *key, void *context);

struct watchpath {
	SLIST_ENTRY(watchpath) sle;
	int fd;
	unsigned int is_qdir:1, __junk:31;
	char name[0];
};

static bool watchpath_new(job_t j, const char *name, bool qdir);
static void watchpath_delete(job_t j, struct watchpath *wp);
static void watchpath_watch(job_t j, struct watchpath *wp);
static void watchpath_ignore(job_t j, struct watchpath *wp);
static void watchpath_callback(job_t j, struct kevent *kev);

struct calendarinterval {
	SLIST_ENTRY(calendarinterval) sle;
	struct tm when;
};

static bool calendarinterval_new(job_t j, struct tm *w);
static bool calendarinterval_new_from_obj(job_t j, launch_data_t obj);
static void calendarinterval_delete(job_t j, struct calendarinterval *ci);
static void calendarinterval_setalarm(job_t j, struct calendarinterval *ci);
static void calendarinterval_callback(job_t j, struct kevent *kev);

struct envitem {
	SLIST_ENTRY(envitem) sle;
	char *value;
	char key[0];
};

static bool envitem_new(job_t j, const char *k, const char *v, bool global);
static void envitem_delete(job_t j, struct envitem *ei, bool global);
static void envitem_setup(launch_data_t obj, const char *key, void *context);

struct limititem {
	SLIST_ENTRY(limititem) sle;
	struct rlimit lim;
	unsigned int setsoft:1, sethard:1, which:30;
};

static bool limititem_update(job_t j, int w, rlim_t r);
static void limititem_delete(job_t j, struct limititem *li);
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

static bool semaphoreitem_new(job_t j, semaphore_reason_t why, const char *what);
static void semaphoreitem_delete(job_t j, struct semaphoreitem *si);
static void semaphoreitem_setup(launch_data_t obj, const char *key, void *context);
static void semaphoreitem_setup_paths(launch_data_t obj, const char *key, void *context);


struct job_s {
	kq_callback kqjob_callback;
	SLIST_ENTRY(job_s) sle;
	SLIST_HEAD(, socketgroup) sockets;
	SLIST_HEAD(, watchpath) vnodes;
	SLIST_HEAD(, calendarinterval) cal_intervals;
	SLIST_HEAD(, envitem) global_env;
	SLIST_HEAD(, envitem) env;
	SLIST_HEAD(, limititem) limits;
	SLIST_HEAD(, machservice) machservices;
	SLIST_HEAD(, semaphoreitem) semaphores;
	SLIST_HEAD(, job_s) jobs;
	struct rusage ru;
	job_t parent;
	mach_port_t bs_port;
	mach_port_t req_port;
	mach_port_t wait_reply_port;
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
	time_t min_run_time;
	unsigned int start_interval;
	unsigned int checkedin:1, firstborn:1, debug:1, inetcompat:1, inetcompat_wait:1,
		     ondemand:1, session_create:1, low_pri_io:1, no_init_groups:1, priv_port_has_senders:1,
		     importing_global_env:1, importing_hard_limits:1, setmask:1, legacy_mach_job:1, runatload:1,
		     anonymous:1;
	mode_t mask;
	unsigned int globargv:1, wait4debugger:1, transfer_bstrap:1, unload_at_exit:1, force_ppc:1,
		     stall_before_exec:1, only_once:1, currently_ignored:1, forced_peers_to_demand_mode:1;
	char label[0];
};

#define job_assumes(j, e)      \
	                (__builtin_expect(!(e), 0) ? job_log_bug(j, __rcs_file_version__, __FILE__, __LINE__, #e), false : true)

static job_t job_import2(launch_data_t pload);
static void job_import_keys(launch_data_t obj, const char *key, void *context);
static void job_import_bool(job_t j, const char *key, bool value);
static void job_import_string(job_t j, const char *key, const char *value);
static void job_import_integer(job_t j, const char *key, long long value);
static void job_import_dictionary(job_t j, const char *key, launch_data_t value);
static void job_import_array(job_t j, const char *key, launch_data_t value);
static void job_dispatch_all(job_t j);
static bool job_set_global_on_demand(job_t j, bool val);
static void job_watch(job_t j);
static void job_ignore(job_t j);
static void job_reap(job_t j);
static bool job_useless(job_t j);
static bool job_keepalive(job_t j);
static void job_start(job_t j);
static void job_start_child(job_t j, int execfd) __attribute__((noreturn));
static void job_setup_attributes(job_t j);
static bool job_setup_machport(job_t j);
static void job_postfork_become_user(job_t j);
static void job_force_sampletool(job_t j);
static void job_callback(void *obj, struct kevent *kev);
static pid_t job_fork(job_t j);
static size_t job_prep_log_preface(job_t j, char *buf);
static void job_setup_env_from_other_jobs(job_t j);
static void job_export_all2(job_t j, launch_data_t where);
static launch_data_t job_export2(job_t j, bool subjobs);
static job_t job_find_by_pid(job_t j, pid_t p, bool recurse);
static job_t job_new_spawn(job_t j, const char *label, const char *path, const char *workingdir, const char *const *argv, const char *const *env, mode_t *u_mask, bool w4d, bool fppc);
static job_t job_new_via_mach_init(job_t jbs, const char *cmd, uid_t uid, bool ond);
static job_t job_new_bootstrap(job_t p, mach_port_t requestorport, mach_port_t checkin_port);
static bool job_new_anonymous(job_t p);
static job_t job_find_anonymous(job_t p);
static const char *job_prog(job_t j);
static pid_t job_get_pid(job_t j);
static mach_port_t job_get_bsport(job_t j);
static mach_port_t job_get_reqport(job_t j);
static job_t job_get_bs(job_t j);
static job_t job_parent(job_t j);
static void job_uncork_fork(job_t j);
static struct machservice *job_lookup_service(job_t jbs, const char *name, bool check_parent);
static void job_foreach_service(job_t jbs, void (*bs_iter)(struct machservice *, void *), void *context, bool only_anonymous);
static void job_logv(job_t j, int pri, int err, const char *msg, va_list ap);
static void job_log(job_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
static void job_log_error(job_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
static void job_log_bug(job_t j, const char *rcs_rev, const char *path, unsigned int line, const char *test);
static kern_return_t job_handle_mpm_wait(job_t j, mach_port_t srp, int *waitstatus);



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

static time_t cronemu(int mon, int mday, int hour, int min);
static time_t cronemu_wday(int wday, int hour, int min);
static bool cronemu_mon(struct tm *wtm, int mon, int mday, int hour, int min);
static bool cronemu_mday(struct tm *wtm, int mday, int hour, int min);
static bool cronemu_hour(struct tm *wtm, int hour, int min);
static bool cronemu_min(struct tm *wtm, int min);

static void simple_zombie_reaper(void *, struct kevent *);

kq_callback kqsimple_zombie_reaper = simple_zombie_reaper;

static int dir_has_files(job_t j, const char *path);
static char **mach_cmd2argv(const char *string);
static size_t global_on_demand_cnt;
job_t root_job;
job_t gc_this_job;
size_t total_children;

void
simple_zombie_reaper(void *obj __attribute__((unused)), struct kevent *kev)
{
	waitpid(kev->ident, NULL, 0);
}

void
job_ignore(job_t j)
{
	struct socketgroup *sg;
	struct machservice *ms;
	struct watchpath *wp;

	if (j->currently_ignored) {
		return;
	}

	j->currently_ignored = true;

	SLIST_FOREACH(sg, &j->sockets, sle) {
		socketgroup_ignore(j, sg);
	}

	SLIST_FOREACH(wp, &j->vnodes, sle) {
		watchpath_ignore(j, wp);
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		job_assumes(j, runtime_remove_mport(ms->port) == KERN_SUCCESS);
	}
}

void
job_watch(job_t j)
{
	struct socketgroup *sg;
	struct machservice *ms;
	struct watchpath *wp;

	if (!job_assumes(j, j->currently_ignored)) {
		return;
	}

	j->currently_ignored = false;

	SLIST_FOREACH(sg, &j->sockets, sle) {
		socketgroup_watch(j, sg);
	}

	SLIST_FOREACH(wp, &j->vnodes, sle) {
		watchpath_watch(j, wp);
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		job_assumes(j, runtime_add_mport(ms->port, NULL, 0) == KERN_SUCCESS);
	}
}

void
job_stop(job_t j)
{
	if (j->p) {
		kill(j->p, SIGTERM);
	}
}

launch_data_t
job_export(job_t j)
{
	return job_export2(j, true);
}

launch_data_t
job_export2(job_t j, bool subjobs)
{
	launch_data_t tmp, tmp2, tmp3, r = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (r == NULL) {
		return NULL;
	}

	if ((tmp = launch_data_new_string(j->label))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LABEL);
	}
	if ((tmp = launch_data_new_bool(j->ondemand))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_ONDEMAND);
	}
	if ((tmp = launch_data_new_integer(j->last_exit_status))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LASTEXITSTATUS);
	} 
	if (j->p && (tmp = launch_data_new_integer(j->p))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PID);
	}
	if ((tmp = launch_data_new_integer(j->timeout))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_TIMEOUT);
	}
	if (j->prog && (tmp = launch_data_new_string(j->prog))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PROGRAM);
	}
	if (j->stdoutpath && (tmp = launch_data_new_string(j->stdoutpath))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_STANDARDOUTPATH);
	}
	if (j->stderrpath && (tmp = launch_data_new_string(j->stderrpath))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_STANDARDERRORPATH);
	}
	if (j->argv && (tmp = launch_data_alloc(LAUNCH_DATA_ARRAY))) {
		int i;

		for (i = 0; i < j->argc; i++) {
			if ((tmp2 = launch_data_new_string(j->argv[i]))) {
				launch_data_array_set_index(tmp, tmp2, i);
			}
		}

		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
	}

	if (j->inetcompat && (tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY))) {
		if ((tmp2 = launch_data_new_bool(j->inetcompat_wait))) {
			launch_data_dict_insert(tmp, tmp2, LAUNCH_JOBINETDCOMPATIBILITY_WAIT);
		}
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_INETDCOMPATIBILITY);
	}

	if (!SLIST_EMPTY(&j->sockets) && (tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY))) {
		struct socketgroup *sg;
		int i;

		SLIST_FOREACH(sg, &j->sockets, sle) {
			if ((tmp2 = launch_data_alloc(LAUNCH_DATA_ARRAY))) {
				for (i = 0; i < sg->fd_cnt; i++) {
					if ((tmp3 = launch_data_new_fd(sg->fds[i]))) {
						launch_data_array_set_index(tmp2, tmp3, i);
					}
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

	if (subjobs && !SLIST_EMPTY(&j->jobs) && (tmp = launch_data_alloc(LAUNCH_DATA_ARRAY))) {
		job_t ji;
		size_t i = 0;

		SLIST_FOREACH(ji, &j->jobs, sle) {
			tmp2 = job_export2(ji, true);
			launch_data_array_set_index(tmp, tmp2, i);
			i++;
		}

		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_SUBJOBS);
	}

	return r;
}

void
job_remove_all_inactive(job_t j)
{
	job_t ji, jn;

	SLIST_FOREACH_SAFE(ji, &j->jobs, sle, jn) {
		job_remove_all_inactive(ji);
	}

	if (!job_active(j)) {
		job_remove(j);
	} else {
		if (debug_shutdown_hangs) {
			job_assumes(j, kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_ADD|EV_ONESHOT, NOTE_SECONDS, 8, j) != -1);
		}
		if (getpid() != 1) {
			job_stop(j);
		}
	}
}

void
job_remove(job_t j)
{
	job_t ji;
	struct calendarinterval *ci;
	struct socketgroup *sg;
	struct watchpath *wp;
	struct limititem *li;
	struct envitem *ei;
	struct machservice *ms;
	struct semaphoreitem *si;

	job_log(j, LOG_DEBUG, "Removed");

	if (j->p && !j->anonymous) {
		if (kevent_mod(j->p, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) == -1) {
			job_reap(j);
		} else {
			/* we've attached the simple zombie reaper, we're going to delete the job before it is dead */
			total_children--;
			job_stop(j);
		}
	}

	if (j->parent) {
		SLIST_REMOVE(&j->parent->jobs, j, job_s, sle);
	}

	if (j->execfd) {
		job_assumes(j, close(j->execfd) == 0);
	}

	if (j->bs_port) {
		if (j->transfer_bstrap) {
			job_assumes(j, launchd_mport_deallocate(j->bs_port) == KERN_SUCCESS);
		} else {
			job_assumes(j, launchd_mport_close_recv(j->bs_port) == KERN_SUCCESS);
		}
	}

	if (j->req_port) {
		job_assumes(j, launchd_mport_deallocate(j->req_port) == KERN_SUCCESS);
	}

#if 0
	if (j->wait_reply_port) {
	}
#endif

	while ((ji = SLIST_FIRST(&j->jobs))) {
		job_remove(ji);
	}
	while ((sg = SLIST_FIRST(&j->sockets))) {
		socketgroup_delete(j, sg);
	}
	while ((wp = SLIST_FIRST(&j->vnodes))) {
		watchpath_delete(j, wp);
	}
	while ((ci = SLIST_FIRST(&j->cal_intervals))) {
		calendarinterval_delete(j, ci);
	}
	while ((ei = SLIST_FIRST(&j->env))) {
		envitem_delete(j, ei, false);
	}
	while ((ei = SLIST_FIRST(&j->global_env))) {
		envitem_delete(j, ei, true);
	}
	while ((li = SLIST_FIRST(&j->limits))) {
		limititem_delete(j, li);
	}
	while ((ms = SLIST_FIRST(&j->machservices))) {
		machservice_delete(ms);
	}
	while ((si = SLIST_FIRST(&j->semaphores))) {
		semaphoreitem_delete(j, si);
	}

	if (j->prog) {
		free(j->prog);
	}
	if (j->argv) {
		free(j->argv);
	}
	if (j->rootdir) {
		free(j->rootdir);
	}
	if (j->workingdir) {
		free(j->workingdir);
	}
	if (j->username) {
		free(j->username);
	}
	if (j->groupname) {
		free(j->groupname);
	}
	if (j->stdinpath) {
		free(j->stdinpath);
	}
	if (j->stdoutpath) {
		free(j->stdoutpath);
	}
	if (j->stderrpath) {
		free(j->stderrpath);
	}
	if (j->start_interval) {
		job_assumes(j, kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_DELETE, 0, 0, NULL) != -1);
	}

	kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	free(j);
}

void
socketgroup_setup(launch_data_t obj, const char *key, void *context)
{
	launch_data_t tmp_oai;
	job_t j = context;
	unsigned int i, fd_cnt = 1;
	int *fds;

	if (launch_data_get_type(obj) == LAUNCH_DATA_ARRAY) {
		fd_cnt = launch_data_array_get_count(obj);
	}

	fds = alloca(fd_cnt * sizeof(int));

	for (i = 0; i < fd_cnt; i++) {
		if (launch_data_get_type(obj) == LAUNCH_DATA_ARRAY) {
			tmp_oai = launch_data_array_get_index(obj, i);
		} else {
			tmp_oai = obj;
		}

		fds[i] = launch_data_get_fd(tmp_oai);
	}

	socketgroup_new(j, key, fds, fd_cnt, strcmp(key, LAUNCH_JOBKEY_BONJOURFDS) == 0);

	ipc_revoke_fds(obj);
}

bool
job_set_global_on_demand(job_t j, bool val)
{
	if (j->forced_peers_to_demand_mode && val) {
		return false;
	} else if (!j->forced_peers_to_demand_mode && !val) {
		return false;
	}

	if ((j->forced_peers_to_demand_mode = val)) {
		global_on_demand_cnt++;
	} else {
		global_on_demand_cnt--;
	}

	if (global_on_demand_cnt == 0) {
		job_dispatch_all(root_job);
	}

	return true;
}

bool
job_setup_machport(job_t j)
{
	mach_msg_size_t mxmsgsz;

	if (!job_assumes(j, launchd_mport_create_recv(&j->bs_port) == KERN_SUCCESS)) {
		goto out_bad;
	}

	/* Sigh... at the moment, MIG has maxsize == sizeof(reply union) */
	mxmsgsz = sizeof(union __RequestUnion__job_mig_protocol_vproc_subsystem);
	if (job_mig_protocol_vproc_subsystem.maxsize > mxmsgsz) {
		mxmsgsz = job_mig_protocol_vproc_subsystem.maxsize;
	}

	if (!job_assumes(j, runtime_add_mport(j->bs_port, protocol_vproc_server, mxmsgsz) == KERN_SUCCESS)) {
		goto out_bad2;
	}

	return true;
out_bad2:
	job_assumes(j, launchd_mport_close_recv(j->bs_port) == KERN_SUCCESS);
out_bad:
	return false;
}

job_t 
job_new_via_mach_init(job_t jbs, const char *cmd, uid_t uid, bool ond)
{
	const char **argv = (const char **)mach_cmd2argv(cmd);
	job_t j = NULL;
	char buf[1000];

	if (!job_assumes(jbs, argv != NULL)) {
		goto out_bad;
	}

	/* preflight the string so we know how big it is */
	snprintf(buf, sizeof(buf), "%s.%s", sizeof(void *) == 8 ? "0xdeadbeeffeedface" : "0xbabecafe", basename((char *)argv[0]));

	j = job_new(jbs, buf, NULL, argv, NULL, MACH_PORT_NULL);

	snprintf(j->label, strlen(j->label) + 1, "%p.%s", j, basename(j->argv[0]));

	free(argv);

	if (!job_assumes(jbs, j != NULL)) {
		goto out_bad;
	}

	j->mach_uid = uid;
	j->ondemand = ond;
	j->legacy_mach_job = true;
	j->priv_port_has_senders = true; /* the IPC that called us will make-send on this port */

	if (!job_setup_machport(j)) {
		goto out_bad;
	}

	if (!job_assumes(j, launchd_mport_notify_req(j->bs_port, MACH_NOTIFY_NO_SENDERS) == KERN_SUCCESS)) {
		job_assumes(j, launchd_mport_close_recv(j->bs_port) == KERN_SUCCESS);
		goto out_bad;
	}

	job_log(j, LOG_INFO, "Legacy%s server created in bootstrap: %x", ond ? " on-demand" : "", jbs->bs_port);

	return j;

out_bad:
	if (j) {
		job_remove(j);
	}
	return NULL;
}

kern_return_t
job_handle_mpm_wait(job_t j, mach_port_t srp, int *waitstatus)
{
	if (j->p) {
		j->wait_reply_port = srp;
		return MIG_NO_REPLY;
	}

	*waitstatus = j->last_exit_status;

	return 0;
}

job_t 
job_new_spawn(job_t j, const char *label, const char *path, const char *workingdir, const char *const *argv, const char *const *env, mode_t *u_mask, bool w4d, bool fppc)
{
	job_t jr;

	if ((jr = job_find(j, label)) != NULL) {
		errno = EEXIST;
		return NULL;
	}

	jr = job_new(j, label, path, argv, NULL, MACH_PORT_NULL);

	if (!jr) {
		return NULL;
	}

	jr->unload_at_exit = true;
	jr->stall_before_exec = w4d;
	jr->force_ppc = fppc;

	if (workingdir) {
		jr->workingdir = strdup(workingdir);
	}

	if (u_mask) {
		jr->mask = *u_mask;
		jr->setmask = true;
	}

	if (env) for (; *env; env++) {
		char newkey[strlen(*env) + 1], *eqoff = strchr(*env, '=');
		if (!eqoff) {
			job_log(jr, LOG_WARNING, "Environmental variable missing '=' separator: %s", *env);
			continue;
		}
		strcpy(newkey, *env);
		*eqoff = '\0';
		envitem_new(jr, newkey, eqoff + 1, false);
	}

	job_dispatch(jr, true);

	return jr;
}

job_t
job_find_anonymous(job_t p)
{
	job_t ji = NULL;

	SLIST_FOREACH(ji, &p->jobs, sle) {
		if (ji->anonymous) {
			break;
		}
	}

	return ji;
}

bool
job_new_anonymous(job_t p)
{
	char newlabel[1000], *procname = "unknown";
	job_t jr;

	snprintf(newlabel, sizeof(newlabel), "%u.anonymous", MACH_PORT_INDEX(p->bs_port));

	if ((jr = job_new(p, newlabel, procname, NULL, NULL, MACH_PORT_NULL))) {
		jr->anonymous = true;
	}

	return jr ? true : false;
}

job_t 
job_new(job_t p, const char *label, const char *prog, const char *const *argv, const char *stdinpath, mach_port_t reqport)
{
	const char *const *argv_tmp = argv;
	char *co;
	int i, cc = 0;
	job_t j;

	if (reqport == MACH_PORT_NULL && prog == NULL && argv == NULL) {
		errno = EINVAL;
		return NULL;
	}

	j = calloc(1, sizeof(struct job_s) + strlen(label) + 1);

	if (!job_assumes(p, j != NULL)) {
		return NULL;
	}

	strcpy(j->label, label);
	j->kqjob_callback = job_callback;
	j->parent = p ? job_get_bs(p) : NULL;
	j->min_run_time = LAUNCHD_MIN_JOB_RUN_TIME;
	j->timeout = LAUNCHD_ADVISABLE_IDLE_TIMEOUT;
	j->currently_ignored = true;
	j->ondemand = true;
	j->checkedin = true;
	j->firstborn = (strcmp(label, FIRSTBORN_LABEL) == 0);

	if (reqport != MACH_PORT_NULL) {
		j->req_port = reqport;
		if (!job_assumes(j, launchd_mport_notify_req(reqport, MACH_NOTIFY_DEAD_NAME) == KERN_SUCCESS)) {
			goto out_bad;
		}
	}

	if (prog) {
		j->prog = strdup(prog);
		if (!job_assumes(j, j->prog != NULL)) {
			goto out_bad;
		}
	}

	if (stdinpath) {
		j->stdinpath = strdup(stdinpath);
		if (!job_assumes(j, j->stdinpath != NULL)) {
			goto out_bad;
		}
	}

	if (argv) {
		while (*argv_tmp++)
			j->argc++;

		for (i = 0; i < j->argc; i++)
			cc += strlen(argv[i]) + 1;

		j->argv = malloc((j->argc + 1) * sizeof(char *) + cc);

		if (!job_assumes(j, j->argv != NULL)) {
			goto out_bad;
		}

		co = ((char *)j->argv) + ((j->argc + 1) * sizeof(char *));

		for (i = 0; i < j->argc; i++) {
			j->argv[i] = co;
			strcpy(co, argv[i]);
			co += strlen(argv[i]) + 1;
		}
		j->argv[i] = NULL;
	}

	if (j->parent) {
		SLIST_INSERT_HEAD(&j->parent->jobs, j, sle);
		job_log(j->parent, LOG_DEBUG, "Conceived");
	}

	return j;

out_bad:
	if (j->prog) {
		free(j->prog);
	}
	if (j->stdinpath) {
		free(j->stdinpath);
	}
	free(j);

	return NULL;
}

job_t 
job_import(launch_data_t pload)
{
	job_t j = job_import2(pload);

	if (j == NULL) {
		return NULL;
	}

	job_dispatch(j, false);

	return j;
}

launch_data_t
job_import_bulk(launch_data_t pload)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_ARRAY);
	job_t *ja;
	size_t i, c = launch_data_array_get_count(pload);

	ja = alloca(c * sizeof(job_t ));

	for (i = 0; i < c; i++) {
		if ((ja[i] = job_import2(launch_data_array_get_index(pload, i)))) {
			errno = 0;
		}
		launch_data_array_set_index(resp, launch_data_new_errno(errno), i);
	}

	for (i = 0; i < c; i++) {
		if (ja[i] == NULL) {
			continue;
		}
		job_dispatch(ja[i], false);
	}

	return resp;
}

void
job_import_bool(job_t j, const char *key, bool value)
{
	switch (key[0]) {
	case 'f':
	case 'F':
		if (strcasecmp(key, LAUNCH_JOBKEY_FORCEPOWERPC) == 0) {
			j->force_ppc = value;
		}
		break;
	case 'k':
	case 'K':
		if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE) == 0) {
			j->ondemand = !value;
		}
		break;
	case 'o':
	case 'O':
		if (strcasecmp(key, LAUNCH_JOBKEY_ONDEMAND) == 0) {
			j->ondemand = value;
		}
		break;
	case 'd':
	case 'D':
		if (strcasecmp(key, LAUNCH_JOBKEY_DEBUG) == 0) {
			j->debug = value;
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_SESSIONCREATE) == 0) {
			j->session_create = value;
		}
		break;
	case 'l':
	case 'L':
		if (strcasecmp(key, LAUNCH_JOBKEY_LOWPRIORITYIO) == 0) {
			j->low_pri_io = value;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LAUNCHONLYONCE) == 0) {
			j->only_once = value;
		}
		break;
	case 'i':
	case 'I':
		if (strcasecmp(key, LAUNCH_JOBKEY_INITGROUPS) == 0) {
			if (getuid() != 0) {
				job_log(j, LOG_WARNING, "Ignored this key: %s", key);
				return;
			}
			j->no_init_groups = !value;
		}
		break;
	case 'r':
	case 'R':
		if (strcasecmp(key, LAUNCH_JOBKEY_RUNATLOAD) == 0) {
			j->runatload = value;
		}
		break;
	case 'e':
	case 'E':
		if (strcasecmp(key, LAUNCH_JOBKEY_ENABLEGLOBBING) == 0) {
			j->globargv = value;
		}
		break;
	case 'w':
	case 'W':
		if (strcasecmp(key, LAUNCH_JOBKEY_WAITFORDEBUGGER) == 0) {
			j->wait4debugger = value;
		}
		break;
	default:
		break;
	}
}

void
job_import_string(job_t j, const char *key, const char *value)
{
	char **where2put = NULL;

	switch (key[0]) {
	case 'p':
	case 'P':
		if (strcasecmp(key, LAUNCH_JOBKEY_PROGRAM) == 0) {
			return;
		}
		break;
	case 'l':
	case 'L':
		if (strcasecmp(key, LAUNCH_JOBKEY_LABEL) == 0) {
			return;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADTOHOSTS) == 0) {
			return;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADFROMHOSTS) == 0) {
			return;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE) == 0) {
			return;
		}
		break;
	case 'r':
	case 'R':
		if (strcasecmp(key, LAUNCH_JOBKEY_ROOTDIRECTORY) == 0) {
			if (getuid() != 0) {
				job_log(j, LOG_WARNING, "Ignored this key: %s", key);
				return;
			}
			where2put = &j->rootdir;
		}
		break;
	case 'w':
	case 'W':
		if (strcasecmp(key, LAUNCH_JOBKEY_WORKINGDIRECTORY) == 0) {
			where2put = &j->workingdir;
		}
		break;
	case 'u':
	case 'U':
		if (strcasecmp(key, LAUNCH_JOBKEY_USERNAME) == 0) {
			if (getuid() != 0) {
				job_log(j, LOG_WARNING, "Ignored this key: %s", key);
				return;
			} else if (strcmp(value, "root") == 0) {
				return;
			}
			where2put = &j->username;
		}
		break;
	case 'g':
	case 'G':
		if (strcasecmp(key, LAUNCH_JOBKEY_GROUPNAME) == 0) {
			if (getuid() != 0) {
				job_log(j, LOG_WARNING, "Ignored this key: %s", key);
				return;
			} else if (strcmp(value, "wheel") == 0) {
				return;
			}
			where2put = &j->groupname;
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_STANDARDOUTPATH) == 0) {
			where2put = &j->stdoutpath;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_STANDARDERRORPATH) == 0) {
			where2put = &j->stderrpath;
		}
		break;
	default:
		break;
	}

	if (where2put) {
		job_assumes(j, (*where2put = strdup(value)) != NULL);
	} else {
		job_log(j, LOG_WARNING, "Unknown key: %s", key);
	}
}

void
job_import_integer(job_t j, const char *key, long long value)
{
	switch (key[0]) {
	case 'n':
	case 'N':
		if (strcasecmp(key, LAUNCH_JOBKEY_NICE) == 0) {
			j->nice = value;
		}
		break;
	case 't':
	case 'T':
		if (strcasecmp(key, LAUNCH_JOBKEY_TIMEOUT) == 0) {
			if (value <= 0) {
				job_log(j, LOG_WARNING, "Timeout less than or equal to zero. Ignoring.");
			} else {
				j->timeout = value;
			}
		} else if (strcasecmp(key, LAUNCH_JOBKEY_THROTTLEINTERVAL) == 0) {
			if (value < 0) {
				job_log(j, LOG_WARNING, "%s less than zero. Ignoring.", LAUNCH_JOBKEY_THROTTLEINTERVAL);
			} else {
				j->min_run_time = value;
			}
		}
		break;
	case 'u':
	case 'U':
		if (strcasecmp(key, LAUNCH_JOBKEY_UMASK) == 0) {
			j->mask = value;
			j->setmask = true;
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_STARTINTERVAL) == 0) {
			if (value <= 0) {
				job_log(j, LOG_WARNING, "StartInterval is not greater than zero, ignoring");
			} else {
				j->start_interval = value;
			}
			if (-1 == kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, value, j)) {
				job_log_error(j, LOG_ERR, "adding kevent timer");
			}
		}
		break;
	default:
		break;
	}
}

void
job_import_dictionary(job_t j, const char *key, launch_data_t value)
{
	launch_data_t tmp;

	switch (key[0]) {
	case 'k':
	case 'K':
		if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE) == 0) {
			launch_data_dict_iterate(value, semaphoreitem_setup, j);
		}
		break;
	case 'i':
	case 'I':
		if (strcasecmp(key, LAUNCH_JOBKEY_INETDCOMPATIBILITY) == 0) {
			j->inetcompat = true;
			if ((tmp = launch_data_dict_lookup(value, LAUNCH_JOBINETDCOMPATIBILITY_WAIT))) {
				j->inetcompat_wait = launch_data_get_bool(tmp);
			}
		}
		break;
	case 'e':
	case 'E':
		if (strcasecmp(key, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES) == 0) {
			launch_data_dict_iterate(value, envitem_setup, j);
		}
		break;
	case 'u':
	case 'U':
		if (strcasecmp(key, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES) == 0) {
			j->importing_global_env = true;
			launch_data_dict_iterate(value, envitem_setup, j);
			j->importing_global_env = false;
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_SOCKETS) == 0) {
			launch_data_dict_iterate(value, socketgroup_setup, j);
		} else if (strcasecmp(key, LAUNCH_JOBKEY_STARTCALENDARINTERVAL) == 0) {
			calendarinterval_new_from_obj(j, value);
		} else if (strcasecmp(key, LAUNCH_JOBKEY_SOFTRESOURCELIMITS) == 0) {
			launch_data_dict_iterate(value, limititem_setup, j);
		}
		break;
	case 'h':
	case 'H':
		if (strcasecmp(key, LAUNCH_JOBKEY_HARDRESOURCELIMITS) == 0) {
			j->importing_hard_limits = true;
			launch_data_dict_iterate(value, limititem_setup, j);
			j->importing_hard_limits = false;
		}
		break;
	case 'm':
	case 'M':
		if (strcasecmp(key, LAUNCH_JOBKEY_MACHSERVICES) == 0) {
			launch_data_dict_iterate(value, machservice_setup, j);
		}
		break;
	default:
		break;
	}
}

void
job_import_array(job_t j, const char *key, launch_data_t value)
{
	bool is_q_dir = false;
	bool is_wp = false;

	switch (key[0]) {
	case 'l':
	case 'L':
		if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADTOHOSTS) == 0) {
			return;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADFROMHOSTS) == 0) {
			return;
		}
		break;
	case 'q':
	case 'Q':
		if (strcasecmp(key, LAUNCH_JOBKEY_QUEUEDIRECTORIES) == 0) {
			is_q_dir = true;
			is_wp = true;
		}
		break;
	case 'w':
	case 'W':
		if (strcasecmp(key, LAUNCH_JOBKEY_WATCHPATHS) == 0) {
			is_wp = true;
		}
		break;
	case 'b':
	case 'B':
		if (strcasecmp(key, LAUNCH_JOBKEY_BONJOURFDS) == 0) {
			socketgroup_setup(value, LAUNCH_JOBKEY_BONJOURFDS, j);
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_STARTCALENDARINTERVAL) == 0) {
			size_t i = 0, ci_cnt = launch_data_array_get_count(value);
			for (i = 0; i < ci_cnt; i++)
				calendarinterval_new_from_obj(j, launch_data_array_get_index(value, i));
		}
		break;
	default:
		break;
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
	job_t j = context;
	launch_data_type_t kind;

	if (obj == NULL) {
		return;
	}

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

job_t 
job_import2(launch_data_t pload)
{
	launch_data_t tmp, ldpa;
	const char *label = NULL, *prog = NULL;
	const char **argv = NULL;
	job_t j;

	if (pload == NULL) {
		return NULL;
	}
	if (launch_data_get_type(pload) != LAUNCH_DATA_DICTIONARY) {
		return NULL;
	}

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
	} else if ((j = job_find(root_job, label)) != NULL) {
		errno = EEXIST;
		return NULL;
	} else if (label[0] == '\0' || (strncasecmp(label, "", strlen("com.apple.launchd")) == 0) ||
			(strtol(label, NULL, 10) != 0)) {
		syslog(LOG_ERR, "Somebody attempted to use a reserved prefix for a label: %s", label);
		/* the empty string, com.apple.launchd and number prefixes for labels are reserved */
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

	if ((j = job_new(root_job, label, prog, argv, NULL, MACH_PORT_NULL))) {
		launch_data_dict_iterate(pload, job_import_keys, j);
	}

	return j;
}

job_t 
job_find(job_t j, const char *label)
{
	job_t jr, ji;

	if (label[0] == '\0') {
		return root_job;
	}

	if (strcmp(j->label, label) == 0) {
		return j;
	}

	SLIST_FOREACH(ji, &j->jobs, sle) {
		if ((jr = job_find(ji, label))) {
			return jr;
		}
	}

	errno = ESRCH;
	return NULL;
}

job_t 
job_find_by_pid(job_t j, pid_t p, bool recurse)
{
	job_t jr, ji;

	if (j->p == p) {
		return j;
	}

	SLIST_FOREACH(ji, &j->jobs, sle) {
		if (ji->p == p) {
			return ji;
		} else if (recurse && (jr = job_find_by_pid(ji, p, recurse))) {
			return jr;
		}
	}

	errno = ESRCH;
	return NULL;
}

static job_t 
job_find_by_port2(job_t j, mach_port_t p)
{
	struct machservice *ms;
	job_t jr, ji;

	if (j->bs_port == p) {
		return j;
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		if (ms->port == p) {
			return j;
		}
	}

	SLIST_FOREACH(ji, &j->jobs, sle) {
		if ((jr = job_find_by_port2(ji, p))) {
			return jr;
		}
	}

	errno = ESRCH;
	return NULL;
}

job_t 
job_mig_intran(mach_port_t p)
{
	struct ldcred ldc;
	job_t jp, jr = NULL;

	runtime_get_caller_creds(&ldc);

	if (launchd_assumes((jp = job_find_by_port2(root_job, p)) != NULL)) {
		if (jp->req_port) {
			if (!(jr = job_find_by_pid(jp, ldc.pid, false))) {
				jr = job_find_anonymous(jp);
			}
		} else {
			jr = jp;
		}
		job_assumes(jp, jr != NULL);
	}

	return jr;
}

void
job_mig_destructor(job_t j __attribute__((unused)))
{
}

void
job_export_all2(job_t j, launch_data_t where)
{
	launch_data_t tmp;
	job_t ji;

	if (job_assumes(j, (tmp = job_export2(j, false)) != NULL)) {
		launch_data_dict_insert(where, tmp, j->label);
	}

	SLIST_FOREACH(ji, &j->jobs, sle)
		job_export_all2(ji, where);
}

launch_data_t
job_export_all(void)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	job_export_all2(root_job, resp);

	return resp;
}

void
job_reap(job_t j)
{
	struct rusage ru;
	int status;

	job_log(j, LOG_DEBUG, "Reaping");

	if (j->execfd) {
		job_assumes(j, close(j->execfd) == 0);
		j->execfd = 0;
	}

	if (!job_assumes(j, wait4(j->p, &status, 0, &ru) != -1)) {
		return;
	}

	if (j->wait_reply_port) {
		job_log(j, LOG_DEBUG, "MPM wait reply being sent");
		job_assumes(j, job_mig_wait_reply(j->wait_reply_port, 0, status) == 0);
		j->wait_reply_port = MACH_PORT_NULL;
	}

	timeradd(&ru.ru_utime, &j->ru.ru_utime, &j->ru.ru_utime);
	timeradd(&ru.ru_stime, &j->ru.ru_stime, &j->ru.ru_stime);
	j->ru.ru_maxrss += ru.ru_maxrss;
	j->ru.ru_ixrss += ru.ru_ixrss;
	j->ru.ru_idrss += ru.ru_idrss;
	j->ru.ru_isrss += ru.ru_isrss;
	j->ru.ru_minflt += ru.ru_minflt;
	j->ru.ru_majflt += ru.ru_majflt;
	j->ru.ru_nswap += ru.ru_nswap;
	j->ru.ru_inblock += ru.ru_inblock;
	j->ru.ru_oublock += ru.ru_oublock;
	j->ru.ru_msgsnd += ru.ru_msgsnd;
	j->ru.ru_msgrcv += ru.ru_msgrcv;
	j->ru.ru_nsignals += ru.ru_nsignals;
	j->ru.ru_nvcsw += ru.ru_nvcsw;
	j->ru.ru_nivcsw += ru.ru_nivcsw;

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		job_log(j, LOG_WARNING, "exited with exit code: %d", WEXITSTATUS(status));
	}

	if (WIFSIGNALED(status)) {
		int s = WTERMSIG(status);
		if (SIGKILL == s || SIGTERM == s) {
			job_log(j, LOG_NOTICE, "Exited: %s", strsignal(s));
		} else {
			job_log(j, LOG_WARNING, "Exited abnormally: %s", strsignal(s));
		}
	}

	total_children--;
	j->last_exit_status = status;
	j->p = 0;
}

void
job_dispatch_all(job_t j)
{
	job_t ji;

	SLIST_FOREACH(ji, &j->jobs, sle) {
		job_dispatch_all(ji);
	}

	job_dispatch(j, false);
}

void
job_dispatch(job_t j, bool kickstart)
{
	/*
	 * The whole job removal logic needs to be consolidated. The fact that
	 * a job can be removed from just about anywhere makes it easy to have
	 * stale pointers left behind somewhere on the stack that might get
	 * used after the deallocation. In particular, during job iteration.
	 *
	 * This is a classic example. The act of dispatching a job may delete it.
	 */
	if (job_active(j)) {
		return;
	} else if (job_useless(j)) {
		job_remove(j);
	} else if (global_on_demand_cnt == 0 && (kickstart || job_keepalive(j))) {
		job_start(j);
	} else {
		job_watch(j);
	}
}

void
job_callback(void *obj, struct kevent *kev)
{
	job_t j = obj;

	switch (kev->filter) {
	case EVFILT_PROC:
		job_reap(j);

		if (j->firstborn) {
			job_log(j, LOG_DEBUG, "first born died, begin shutdown");
			launchd_shutdown();
		} else {
			job_dispatch(j, false);
		}
		break;
	case EVFILT_TIMER:
		if ((uintptr_t)j == kev->ident) {
			if (j->p && job_assumes(j, debug_shutdown_hangs)) {
				job_force_sampletool(j);
			} else {
				job_dispatch(j, true);
			}
		} else if ((uintptr_t)&j->start_interval == kev->ident) {
			job_dispatch(j, true);
		} else {
			calendarinterval_callback(j, kev);
		}
		break;
	case EVFILT_VNODE:
		watchpath_callback(j, kev);
		break;
	case EVFILT_READ:
		if ((int)kev->ident != j->execfd) {
			socketgroup_callback(j, kev);
			break;
		}
		if (j->wait4debugger) {
			/* Allow somebody else to attach */
			job_assumes(j, kill(j->p, SIGSTOP) != -1);
			job_assumes(j, ptrace(PT_DETACH, j->p, NULL, 0) != -1);
		}
		if (kev->data > 0) {
			int e;

			read(j->execfd, &e, sizeof(e));
			errno = e;
			job_log_error(j, LOG_ERR, "execve()");
			job_remove(j);
			j = NULL;
		} else {
			job_assumes(j, close(j->execfd) == 0);
			j->execfd = 0;
		}
		break;
	case EVFILT_MACHPORT:
		job_dispatch(j, true);
		break;
	default:
		job_assumes(j, false);
		break;
	}
}

void
job_start(job_t j)
{
	int spair[2];
	int execspair[2];
	char nbuf[64];
	pid_t c;
	bool sipc = false;
	time_t td;

	if (!job_assumes(j, j->req_port == MACH_PORT_NULL)) {
		return;
	}

	if (!job_assumes(j, j->parent != NULL)) {
		return;
	}

	if (job_active(j)) {
		job_log(j, LOG_DEBUG, "Already started");
		return;
	}

	td = time(NULL) - j->start_time;

	if (td < j->min_run_time && !j->legacy_mach_job && !j->inetcompat) {
		time_t respawn_delta = j->min_run_time - td;

		job_log(j, LOG_WARNING, "Throttling respawn: Will start in %ld seconds", respawn_delta);
		job_assumes(j, kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_ADD|EV_ONESHOT, NOTE_SECONDS, respawn_delta, j) != -1);
		job_ignore(j);
		return;
	}

	job_log(j, LOG_DEBUG, "Starting");

	/* FIXME, using stdinpath is a hack for re-reading the conf file */
	if (j->stdinpath) {
	       sipc = true;
	} else if (!j->legacy_mach_job) {
		sipc = (!SLIST_EMPTY(&j->sockets) || !SLIST_EMPTY(&j->machservices));
	}


	j->checkedin = false;

	if (sipc) {
		socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
	}

	socketpair(AF_UNIX, SOCK_STREAM, 0, execspair);

	time(&j->start_time);

	switch (c = job_fork(j->parent)) {
	case -1:
		job_log_error(j, LOG_ERR, "fork() failed, will try again in one second");
		job_assumes(j, close(execspair[0]) == 0);
		job_assumes(j, close(execspair[1]) == 0);
		if (sipc) {
			job_assumes(j, close(spair[0]) == 0);
			job_assumes(j, close(spair[1]) == 0);
		}
		break;
	case 0:
		job_assumes(j, close(execspair[0]) == 0);
		/* wait for our parent to say they've attached a kevent to us */
		read(_fd(execspair[1]), &c, sizeof(c));
		if (j->firstborn) {
			setpgid(getpid(), getpid());
			if (isatty(STDIN_FILENO)) {
				if (tcsetpgrp(STDIN_FILENO, getpid()) == -1) {
					job_log_error(j, LOG_WARNING, "tcsetpgrp()");
				}
			}
		}

		if (sipc) {
			job_assumes(j, close(spair[0]) == 0);
			snprintf(nbuf, sizeof(nbuf), "%d", spair[1]);
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
		}
		job_start_child(j, execspair[1]);
		break;
	default:
		j->p = c;
		total_children++;
		job_assumes(j, close(execspair[1]) == 0);
		j->execfd = _fd(execspair[0]);
		if (sipc) {
			job_assumes(j, close(spair[1]) == 0);
			ipc_open(_fd(spair[0]), j);
		}
		if (kevent_mod(j->execfd, EVFILT_READ, EV_ADD, 0, 0, &j->kqjob_callback) == -1) {
			job_log_error(j, LOG_ERR, "kevent_mod(j->execfd): %m");
		}
		if (kevent_mod(c, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &j->kqjob_callback) == -1) {
			job_log_error(j, LOG_ERR, "kevent()");
			job_reap(j);
		} else {
		       	if (j->ondemand) {
				job_ignore(j);
			}
		}

		if (!j->stall_before_exec) {
			/* this unblocks the child and avoids a race
			 * between the above fork() and the kevent_mod() */
			write(j->execfd, &c, sizeof(c));
		}
		break;
	}
}

void
job_start_child(job_t j, int execfd)
{
	const char *file2exec = "/usr/libexec/launchproxy";
	const char **argv;
	int gflags = GLOB_NOSORT|GLOB_NOCHECK|GLOB_TILDE|GLOB_DOOFFS;
	glob_t g;
	int i;

	job_setup_attributes(j);

	if (j->argv && j->globargv) {
		g.gl_offs = 1;
		for (i = 0; i < j->argc; i++) {
			if (i > 0) {
				gflags |= GLOB_APPEND;
			}
			if (glob(j->argv[i], gflags, NULL, &g) != 0) {
				job_log_error(j, LOG_ERR, "glob(\"%s\")", j->argv[i]);
				exit(EXIT_FAILURE);
			}
		}
		g.gl_pathv[0] = (char *)file2exec;
		argv = (const char **)g.gl_pathv;
	} else if (j->argv) {
		argv = alloca((j->argc + 2) * sizeof(char *));
		argv[0] = file2exec;
		for (i = 0; i < j->argc; i++)
			argv[i + 1] = j->argv[i];
		argv[i + 1] = NULL;
	} else {
		argv = alloca(3 * sizeof(char *));
		argv[0] = file2exec;
		argv[1] = j->prog;
		argv[2] = NULL;
	}

	if (!j->inetcompat) {
		argv++;
	}

	if (j->wait4debugger && ptrace(PT_TRACE_ME, getpid(), NULL, 0) == -1) {
		job_log_error(j, LOG_ERR, "ptrace(PT_TRACE_ME, ...)");
	}

	if (j->force_ppc) {
		int affinmib[] = { CTL_KERN, KERN_AFFINITY, 1, 1 };
		size_t mibsz = sizeof(affinmib) / sizeof(affinmib[0]);

		if (sysctl(affinmib, mibsz, NULL, NULL,  NULL, 0) == -1) {
			job_log_error(j, LOG_WARNING, "Failed to force PowerPC execution");
		}
	}

	if (j->prog) {
		execv(j->inetcompat ? file2exec : j->prog, (char *const*)argv);
		job_log_error(j, LOG_ERR, "execv(\"%s\", ...)", j->prog);
	} else {
		execvp(j->inetcompat ? file2exec : argv[0], (char *const*)argv);
		job_log_error(j, LOG_ERR, "execvp(\"%s\", ...)", argv[0]);
	}

	write(execfd, &errno, sizeof(errno));
	exit(EXIT_FAILURE);
}

void job_setup_env_from_other_jobs(job_t j)
{
	struct envitem *ei;
	job_t ji;

	SLIST_FOREACH(ji, &j->jobs, sle)
		job_setup_env_from_other_jobs(ji);

	SLIST_FOREACH(ei, &j->global_env, sle)
		setenv(ei->key, ei->value, 1);
}

void
job_postfork_become_user(job_t j)
{
	char loginname[2000];
	struct passwd *pwe;
	gid_t desired_gid = -1;
	uid_t desired_uid = -1;

	if (getuid() != 0) {
		return;
	}

	if (j->username) {
		if ((pwe = getpwnam(j->username)) == NULL) {
			job_log(j, LOG_ERR, "getpwnam(\"%s\") failed", j->username);
			_exit(EXIT_FAILURE);
		}
	} else if (j->mach_uid) {
		if ((pwe = getpwuid(j->mach_uid)) == NULL) {
			job_log(j, LOG_ERR, "getpwuid(\"%u\") failed", j->mach_uid);
			_exit(EXIT_FAILURE);
		}
	} else {
		return;
	}

	strlcpy(loginname, pwe->pw_name, sizeof(loginname));

	if (pwe->pw_expire && time(NULL) >= pwe->pw_expire) {
		job_log(j, LOG_ERR, "Expired account");
		_exit(EXIT_FAILURE);
	}

	desired_uid = pwe->pw_uid;
	desired_gid = pwe->pw_gid;

	if (j->groupname) {
		struct group *gre;

		if ((gre = getgrnam(j->groupname)) == NULL) {
			job_log(j, LOG_ERR, "getgrnam(\"%s\") failed", j->groupname);
			_exit(EXIT_FAILURE);
		}

		desired_gid = gre->gr_gid;
	}

	if (-1 == setgid(desired_gid)) {
		job_log_error(j, LOG_ERR, "setgid(%u)", desired_gid);
		_exit(EXIT_FAILURE);
	}

	/*
	 * <rdar://problem/4616864> launchctl should invoke initgroups after setgid
	 */

	if (!j->no_init_groups) {
		if (initgroups(loginname, desired_gid) == -1) {
			job_log_error(j, LOG_ERR, "initgroups()");
			_exit(EXIT_FAILURE);
		}
	}

	if (-1 == setuid(desired_uid)) {
		job_log_error(j, LOG_ERR, "setuid(%u)", desired_uid);
		_exit(EXIT_FAILURE);
	}
}

void
job_setup_attributes(job_t j)
{
	struct limititem *li;
	struct envitem *ei;

	setpriority(PRIO_PROCESS, 0, j->nice);

	SLIST_FOREACH(li, &j->limits, sle) {
		struct rlimit rl;

		if (getrlimit(li->which, &rl) == -1) {
			job_log_error(j, LOG_WARNING, "getrlimit()");
			continue;
		}

		if (li->sethard) {
			rl.rlim_max = li->lim.rlim_max;
		}
		if (li->setsoft) {
			rl.rlim_cur = li->lim.rlim_cur;
		}

		if (setrlimit(li->which, &rl) == -1) {
			job_log_error(j, LOG_WARNING, "setrlimit()");
		}
	}

	if (!j->inetcompat && j->session_create) {
		launchd_SessionCreate();
	}

	if (j->low_pri_io) {
		if (setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE) == -1) {
			job_log_error(j, LOG_WARNING, "setiopolicy_np()");
		}
	}
	if (j->rootdir) {
		chroot(j->rootdir);
		chdir(".");
	}

	job_postfork_become_user(j);

	if (j->workingdir) {
		chdir(j->workingdir);
	}

	if (j->setmask) {
		umask(j->mask);
	}

	if (j->stdinpath) {
		int sifd = open(j->stdinpath, O_RDONLY|O_NOCTTY);
		if (sifd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", j->stdinpath);
		} else {
			job_assumes(j, dup2(sifd, STDIN_FILENO) != -1);
			job_assumes(j, close(sifd) == 0);
		}
	}
	if (j->stdoutpath) {
		int sofd = open(j->stdoutpath, O_WRONLY|O_APPEND|O_CREAT|O_NOCTTY, DEFFILEMODE);
		if (sofd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", j->stdoutpath);
		} else {
			job_assumes(j, dup2(sofd, STDOUT_FILENO) != -1);
			job_assumes(j, close(sofd) == 0);
		}
	}
	if (j->stderrpath) {
		int sefd = open(j->stderrpath, O_WRONLY|O_APPEND|O_CREAT|O_NOCTTY, DEFFILEMODE);
		if (sefd == -1) {
			job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", j->stderrpath);
		} else {
			job_assumes(j, dup2(sefd, STDERR_FILENO) != -1);
			job_assumes(j, close(sefd) == 0);
		}
	}

	job_setup_env_from_other_jobs(root_job);

	SLIST_FOREACH(ei, &j->env, sle)
		setenv(ei->key, ei->value, 1);

	setsid();
}

int
dir_has_files(job_t j, const char *path)
{
	DIR *dd = opendir(path);
	struct dirent *de;
	bool r = 0;

	if (!dd) {
		return -1;
	}

	while ((de = readdir(dd))) {
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			r = 1;
			break;
		}
	}

	job_assumes(j, closedir(dd) == 0);
	return r;
}

void
calendarinterval_setalarm(job_t j, struct calendarinterval *ci)
{
	time_t later;

	later = cronemu(ci->when.tm_mon, ci->when.tm_mday, ci->when.tm_hour, ci->when.tm_min);

	if (ci->when.tm_wday != -1) {
		time_t otherlater = cronemu_wday(ci->when.tm_wday, ci->when.tm_hour, ci->when.tm_min);

		if (ci->when.tm_mday == -1) {
			later = otherlater;
		} else {
			later = later < otherlater ? later : otherlater;
		}
	}

	if (-1 == kevent_mod((uintptr_t)ci, EVFILT_TIMER, EV_ADD, NOTE_ABSOLUTE|NOTE_SECONDS, later, j)) {
		job_log_error(j, LOG_ERR, "adding kevent alarm");
	} else {
		job_log(j, LOG_INFO, "scheduled to run again at %s", ctime(&later));
	}
}

size_t
job_prep_log_preface(job_t j, char *buf)
{
	size_t lsz = strlen(j->label);
	char newlabel[lsz * 2 + 1];
	size_t i, o, r = 0;

	for (i = 0, o = 0; i < lsz; i++, o++) {
		if (j->label[i] == '%') {
			newlabel[o] = '%';
			o++;
			newlabel[o] = '%';
		} else {
			newlabel[o] = j->label[i];
		}
	}
	newlabel[o] = '\0';

	if (j->parent) {
		r = job_prep_log_preface(j->parent, buf);
	}

	return r + sprintf(buf + r, "%s%s", j->parent ? "/" : "", newlabel);
}

void
job_log_bug(job_t j, const char *rcs_rev, const char *path, unsigned int line, const char *test)
{
	int saved_errno = errno;
	char buf[100];
	const char *file = strrchr(path, '/');
	char *rcs_rev_tmp = strchr(rcs_rev, ' ');

	if (!file) {
		file = path;
	} else {
		file += 1;
	}

	if (!rcs_rev_tmp) {
		strlcpy(buf, rcs_rev, sizeof(buf));
	} else {
		strlcpy(buf, rcs_rev_tmp + 1, sizeof(buf));
		rcs_rev_tmp = strchr(buf, ' ');
		if (rcs_rev_tmp) {
			*rcs_rev_tmp = '\0';
		}
	}

	job_log(j, LOG_NOTICE, "Bug: %s:%u (%s):%u: %s", file, line, buf, saved_errno, test);
}

void
job_logv(job_t j, int pri, int err, const char *msg, va_list ap)
{
	char newmsg[10000];
	int oldmask = 0;
	size_t o;

	/*
	 * Hack: If bootstrap_port is set, we must be on the child side of a
	 * fork(), but before the exec*(). Let's route the log message back to
	 * launchd proper.
	 */
	if (bootstrap_port) {
		return _vproc_logv(pri, err, msg, ap);
	}

	o = job_prep_log_preface(j, newmsg);

	if (err) {
		snprintf(newmsg + o, sizeof(newmsg) - o, ": %s: %s", msg, strerror(err));
	} else {
		snprintf(newmsg + o, sizeof(newmsg) - o, ": %s", msg);
	}

	if (j->debug) {
		oldmask = setlogmask(LOG_UPTO(LOG_DEBUG));
	}

	vsyslog(pri, newmsg, ap);

	if (j->debug) {
		setlogmask(oldmask);
	}
}

void
job_log_error(job_t j, int pri, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	job_logv(j, pri, errno, msg, ap);
	va_end(ap);
}

void
job_log(job_t j, int pri, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	job_logv(j, pri, 0, msg, ap);
	va_end(ap);
}

bool
watchpath_new(job_t j, const char *name, bool qdir)
{
	struct watchpath *wp = calloc(1, sizeof(struct watchpath) + strlen(name) + 1);

	if (!job_assumes(j, wp != NULL)) {
		return false;
	}

	wp->is_qdir = qdir;

	wp->fd = -1; /* watchpath_watch() will open this */

	strcpy(wp->name, name);

	SLIST_INSERT_HEAD(&j->vnodes, wp, sle);

	return true;
}       

void
watchpath_delete(job_t j, struct watchpath *wp) 
{
	if (wp->fd != -1) {
		job_assumes(j, close(wp->fd) != -1);
	}

	SLIST_REMOVE(&j->vnodes, wp, watchpath, sle);

	free(wp);
}       

void    
watchpath_ignore(job_t j, struct watchpath *wp)
{       
	if (wp->fd != -1) {
		job_log(j, LOG_DEBUG, "Ignoring Vnode: %d", wp->fd);
		job_assumes(j, kevent_mod(wp->fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL) != -1);
	}
}

void
watchpath_watch(job_t j, struct watchpath *wp)
{
	int fflags = NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_LINK;
	int qdir_file_cnt;

	if (!wp->is_qdir) {
		fflags |= NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE;
	}

	if (wp->fd == -1) {
		wp->fd = _fd(open(wp->name, O_EVTONLY|O_NOCTTY|O_NOFOLLOW));
	}

	if (wp->fd == -1) {
		return job_log_error(j, LOG_ERR, "Watchpath monitoring failed on \"%s\"", wp->name);
	}

	job_log(j, LOG_DEBUG, "Watching Vnode: %d", wp->fd);
	job_assumes(j, kevent_mod(wp->fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, fflags, 0, j) != -1);

	if (!wp->is_qdir) {
		return;
	}

	if (-1 == (qdir_file_cnt = dir_has_files(j, wp->name))) {
		job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", wp->name);
	} else if (qdir_file_cnt > 0) {
		job_dispatch(j, true);
	}
}

void
watchpath_callback(job_t j, struct kevent *kev)
{
	struct watchpath *wp;
	int dir_file_cnt;

	SLIST_FOREACH(wp, &j->vnodes, sle) {
		if (wp->fd == (int)kev->ident) {
			break;
		}
	}

	job_assumes(j, wp != NULL);

	if ((NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE) & kev->fflags) {
		job_log(j, LOG_DEBUG, "Path invalidated: %s", wp->name);
		job_assumes(j, close(wp->fd) == 0);
		wp->fd = -1; /* this will get fixed in watchpath_watch() */
	} else if (!wp->is_qdir) {
		job_log(j, LOG_DEBUG, "Watch path modified: %s", wp->name);
	} else {
		job_log(j, LOG_DEBUG, "Queue directory modified: %s", wp->name);

		if (-1 == (dir_file_cnt = dir_has_files(j, wp->name))) {
			job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", wp->name);
		} else if (0 == dir_file_cnt) {
			job_log(j, LOG_DEBUG, "Spurious wake up, directory is empty again: %s", wp->name);
			return;
		}
	}

	job_dispatch(j, true);
}

bool
calendarinterval_new_from_obj(job_t j, launch_data_t obj)
{
	launch_data_t tmp_k;
	struct tm tmptm;

	memset(&tmptm, 0, sizeof(0));

	tmptm.tm_min = -1;
	tmptm.tm_hour = -1;
	tmptm.tm_mday = -1;
	tmptm.tm_wday = -1;
	tmptm.tm_mon = -1;

	if (LAUNCH_DATA_DICTIONARY != launch_data_get_type(obj)) {
		return false;
	}

	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_MINUTE))) {
		tmptm.tm_min = launch_data_get_integer(tmp_k);
	}
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_HOUR))) {
		tmptm.tm_hour = launch_data_get_integer(tmp_k);
	}
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_DAY))) {
		tmptm.tm_mday = launch_data_get_integer(tmp_k);
	}
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_WEEKDAY))) {
		tmptm.tm_wday = launch_data_get_integer(tmp_k);
	}
	if ((tmp_k = launch_data_dict_lookup(obj, LAUNCH_JOBKEY_CAL_MONTH))) {
		tmptm.tm_mon = launch_data_get_integer(tmp_k);
	}

	return calendarinterval_new(j, &tmptm);
}

bool
calendarinterval_new(job_t j, struct tm *w)
{
	struct calendarinterval *ci = calloc(1, sizeof(struct calendarinterval));

	if (!job_assumes(j, ci != NULL)) {
		return false;
	}

	ci->when = *w;

	SLIST_INSERT_HEAD(&j->cal_intervals, ci, sle);

	calendarinterval_setalarm(j, ci);

	return true;
}

void
calendarinterval_delete(job_t j, struct calendarinterval *ci)
{
	job_assumes(j, kevent_mod((uintptr_t)ci, EVFILT_TIMER, EV_DELETE, 0, 0, NULL) != -1);

	SLIST_REMOVE(&j->cal_intervals, ci, calendarinterval, sle);

	free(ci);
}

void
calendarinterval_callback(job_t j, struct kevent *kev)
{
	struct calendarinterval *ci;

	SLIST_FOREACH(ci, &j->cal_intervals, sle) {
		if ((uintptr_t)ci == kev->ident) {
			break;
		}
	}

	if (job_assumes(j, ci != NULL)) {
		calendarinterval_setalarm(j, ci);
		job_dispatch(j, true);
	}
}

bool
socketgroup_new(job_t j, const char *name, int *fds, unsigned int fd_cnt, bool junkfds)
{
	struct socketgroup *sg = calloc(1, sizeof(struct socketgroup) + strlen(name) + 1);

	if (!job_assumes(j, sg != NULL)) {
		return false;
	}

	sg->fds = calloc(1, fd_cnt * sizeof(int));
	sg->fd_cnt = fd_cnt;
	sg->junkfds = junkfds;

	if (!job_assumes(j, sg->fds != NULL)) {
		free(sg);
		return false;
	}

	memcpy(sg->fds, fds, fd_cnt * sizeof(int));
	strcpy(sg->name, name);

	SLIST_INSERT_HEAD(&j->sockets, sg, sle);

	return true;
}

void
socketgroup_delete(job_t j, struct socketgroup *sg)
{
	unsigned int i;

	for (i = 0; i < sg->fd_cnt; i++)
		job_assumes(j, close(sg->fds[i]) != -1);

	SLIST_REMOVE(&j->sockets, sg, socketgroup, sle);

	free(sg->fds);
	free(sg);
}

void
socketgroup_ignore(job_t j, struct socketgroup *sg)
{
	char buf[10000];
	unsigned int i, buf_off = 0;

	if (sg->junkfds) {
		return;
	}

	for (i = 0; i < sg->fd_cnt; i++)
		buf_off += snprintf(buf + buf_off, sizeof(buf) - buf_off, " %d", sg->fds[i]);

	job_log(j, LOG_DEBUG, "Ignoring Sockets:%s", buf);

	for (i = 0; i < sg->fd_cnt; i++)
		job_assumes(j, kevent_mod(sg->fds[i], EVFILT_READ, EV_DELETE, 0, 0, NULL) != -1);
}

void
socketgroup_watch(job_t j, struct socketgroup *sg)
{
	char buf[10000];
	unsigned int i, buf_off = 0;

	if (sg->junkfds) {
		return;
	}

	for (i = 0; i < sg->fd_cnt; i++)
		buf_off += snprintf(buf + buf_off, sizeof(buf) - buf_off, " %d", sg->fds[i]);

	job_log(j, LOG_DEBUG, "Watching sockets:%s", buf);

	for (i = 0; i < sg->fd_cnt; i++)
		job_assumes(j, kevent_mod(sg->fds[i], EVFILT_READ, EV_ADD, 0, 0, j) != -1);
}

void
socketgroup_callback(job_t j, struct kevent *kev)
{
	job_dispatch(j, true);
}

bool
envitem_new(job_t j, const char *k, const char *v, bool global)
{
	struct envitem *ei = calloc(1, sizeof(struct envitem) + strlen(k) + 1 + strlen(v) + 1);

	if (!job_assumes(j, ei != NULL)) {
		return false;
	}

	strcpy(ei->key, k);
	ei->value = ei->key + strlen(k) + 1;
	strcpy(ei->value, v);

	if (global) {
		SLIST_INSERT_HEAD(&j->global_env, ei, sle);
	} else {
		SLIST_INSERT_HEAD(&j->env, ei, sle);
	}

	return true;
}

void
envitem_delete(job_t j, struct envitem *ei, bool global)
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
	job_t j = context;

	if (launch_data_get_type(obj) != LAUNCH_DATA_STRING) {
		return;
	}

	envitem_new(j, key, launch_data_get_string(obj), j->importing_global_env);
}

bool
limititem_update(job_t j, int w, rlim_t r)
{
	struct limititem *li;

	SLIST_FOREACH(li, &j->limits, sle) {
		if (li->which == w) {
			break;
		}
	}

	if (li == NULL) {
		li = calloc(1, sizeof(struct limititem));

		if (!job_assumes(j, li != NULL)) {
			return false;
		}

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
limititem_delete(job_t j, struct limititem *li)
{
	SLIST_REMOVE(&j->limits, li, limititem, sle);

	free(li);
}

void
limititem_setup(launch_data_t obj, const char *key, void *context)
{
	job_t j = context;
	int i, limits_cnt = (sizeof(launchd_keys2limits) / sizeof(launchd_keys2limits[0]));
	rlim_t rl;

	if (launch_data_get_type(obj) != LAUNCH_DATA_INTEGER) {
		return;
	}

	rl = launch_data_get_integer(obj);

	for (i = 0; i < limits_cnt; i++) {
		if (strcasecmp(launchd_keys2limits[i].key, key) == 0) {
			break;
		}
	}

	if (i == limits_cnt) {
		return;
	}

	limititem_update(j, launchd_keys2limits[i].val, rl);
}

bool
job_useless(job_t j)
{
	/* Yes, j->unload_at_exit and j->j->only_once seem the same, but they'll differ someday... */

	if ((j->unload_at_exit || j->only_once) && j->start_time != 0) {
		job_log(j, LOG_INFO, "Exited. Was only configured to run once.");
		return true;
	} else if (shutdown_in_progress) {
		job_log(j, LOG_INFO, "Exited while shutdown in progress.");
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
job_keepalive(job_t j)
{
	mach_msg_type_number_t statusCnt;
	mach_port_status_t status;
	struct semaphoreitem *si;
	struct machservice *ms;
	struct stat sb;
	bool good_exit = (WIFEXITED(j->last_exit_status) && WEXITSTATUS(j->last_exit_status) == 0);
	bool dispatch_others = false;

	if (j->runatload && j->start_time == 0) {
		job_log(j, LOG_DEBUG, "KeepAlive check: job needs to run at least once.");
		return true;
	}

	if (!j->ondemand) {
		job_log(j, LOG_DEBUG, "KeepAlive check: job configured to run continuously.");
		return true;
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
		if (mach_port_get_attributes(mach_task_self(), ms->port, MACH_PORT_RECEIVE_STATUS,
					(mach_port_info_t)&status, &statusCnt) != KERN_SUCCESS)
			continue;
		if (status.mps_msgcount) {
			job_log(j, LOG_DEBUG, "KeepAlive check: job restarted due to %d queued Mach messages on service: %s",
					status.mps_msgcount, ms->name);
			return true;
		}
	}


	SLIST_FOREACH(si, &j->semaphores, sle) {
		bool wanted_state = false;
		switch (si->why) {
		case NETWORK_UP:
			wanted_state = true;
		case NETWORK_DOWN:
			if (network_up == wanted_state) {
				job_log(j, LOG_DEBUG, "KeepAlive check: job configured to run while the network is %s.",
						wanted_state ? "up" : "down");
				return true;
			}
			break;
		case SUCCESSFUL_EXIT:
			wanted_state = true;
		case FAILED_EXIT:
			if (good_exit == wanted_state) {
				job_log(j, LOG_DEBUG, "KeepAlive check: job configured to run while the exit state was %s.",
						wanted_state ? "successful" : "failure");
				return true;
			}
			break;
		case PATH_EXISTS:
			wanted_state = true;
		case PATH_MISSING:
			if ((bool)(stat(si->what, &sb) == 0) == wanted_state) {
				job_log(j, LOG_DEBUG, "KeepAlive check: job configured to run while the following path %s: %s",
						wanted_state ? "exists" : "is missing", si->what);
				return true;
			}
			dispatch_others = true;
			break;
		}
	}

	/* Maybe another job has the inverse path based semaphore as this job */
	if (dispatch_others) {
		job_dispatch_all_other_semaphores(root_job, j);
	}

	return false;
}

const char *
job_prog(job_t j)
{
	if (j->prog) {
		return j->prog;
	} else if (j->argv) {
		return j->argv[0];
	} else {
		return "";
	}
}

bool
job_active(job_t j)
{
	struct machservice *ms;

	if (j->anonymous) {
		return true;
	}

	if (j->req_port) {
		return true;
	}

	if (j->p) {
		return true;
	}

	if (j->priv_port_has_senders) {
		return true;
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		if (ms->isActive) {
			return true;
		}
	}

	return false;
}

pid_t
launchd_fork(void)
{
	return job_fork(root_job);
}

pid_t
job_fork(job_t j)
{
	mach_port_t p = j->bs_port;
	pid_t r = -1;

	sigprocmask(SIG_BLOCK, &blocked_signals, NULL);

	job_assumes(j, launchd_mport_make_send(p) == KERN_SUCCESS);
	job_assumes(j, launchd_set_bport(p) == KERN_SUCCESS);
	job_assumes(j, launchd_mport_deallocate(p) == KERN_SUCCESS);

	r = fork();

	if (r != 0) {
		job_assumes(j, launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);
	} else if (r == 0) {
		size_t i;

		for (i = 0; i < NSIG; i++) {
			if (sigismember(&blocked_signals, i)) {
				signal(i, SIG_DFL);
			}
		}
	}

	sigprocmask(SIG_UNBLOCK, &blocked_signals, NULL);
	
	return r;
}

void
machservice_resetport(job_t j, struct machservice *ms)
{
	job_assumes(j, launchd_mport_close_recv(ms->port) == KERN_SUCCESS);
	job_assumes(j, launchd_mport_deallocate(ms->port) == KERN_SUCCESS);
	job_assumes(j, launchd_mport_create_recv(&ms->port) == KERN_SUCCESS);
	job_assumes(j, launchd_mport_make_send(ms->port) == KERN_SUCCESS);
}

struct machservice *
machservice_new(job_t j, const char *name, mach_port_t *serviceport)
{
	struct machservice *ms;

	if ((ms = calloc(1, sizeof(struct machservice) + strlen(name) + 1)) == NULL) {
		return NULL;
	}

	strcpy(ms->name, name);
	ms->job = j;

	if (*serviceport == MACH_PORT_NULL) {
		if (!job_assumes(j, launchd_mport_create_recv(&ms->port) == KERN_SUCCESS)) {
			goto out_bad;
		}

		if (!job_assumes(j, launchd_mport_make_send(ms->port) == KERN_SUCCESS)) {
			goto out_bad2;
		}
		*serviceport = ms->port;
		ms->recv = true;
	} else {
		ms->port = *serviceport;
		ms->isActive = true;
	}

	SLIST_INSERT_HEAD(&j->machservices, ms, sle);

	job_log(j, LOG_INFO, "Mach service added: %s", name);

	return ms;
out_bad2:
	job_assumes(j, launchd_mport_close_recv(ms->port) == KERN_SUCCESS);
out_bad:
	free(ms);
	return NULL;
}

bootstrap_status_t
machservice_status(struct machservice *ms)
{
	if (ms->isActive) {
		return BOOTSTRAP_STATUS_ACTIVE;
	} else if (ms->job->ondemand) {
		return BOOTSTRAP_STATUS_ON_DEMAND;
	} else {
		return BOOTSTRAP_STATUS_INACTIVE;
	}
}

void
machservice_setup_options(launch_data_t obj, const char *key, void *context)
{
	struct machservice *ms = context;
	mach_port_t mhp = mach_host_self();
	mach_port_t mts = mach_task_self();
	thread_state_flavor_t f = 0;
	exception_mask_t em;
	int which_port;
	bool b;

#if defined (__ppc__)
	f = PPC_THREAD_STATE64;
#elif defined(__i386__)
	f = x86_THREAD_STATE;
#endif

#if defined(EXC_MASK_CRASH)
	em = EXC_MASK_CRASH;
#else
	em = EXC_MASK_RPC_ALERT;
#endif

	if (!job_assumes(ms->job, mhp != MACH_PORT_NULL)) {
		return;
	}

	switch (launch_data_get_type(obj)) {
	case LAUNCH_DATA_INTEGER:
		which_port = launch_data_get_integer(obj);
		if (strcasecmp(key, LAUNCH_JOBKEY_MACH_TASKSPECIALPORT) == 0) {
			switch (which_port) {
			case TASK_KERNEL_PORT:
			case TASK_HOST_PORT:
			case TASK_NAME_PORT:
			case TASK_BOOTSTRAP_PORT:
			/* I find it a little odd that zero isn't reserved in the header */
			case 0:
				job_log(ms->job, LOG_WARNING, "Tried to set a reserved task special port: %d", which_port);
				break;
			default:
				job_assumes(ms->job, (errno = task_set_special_port(mts, which_port, ms->port)) == KERN_SUCCESS);
				break;
			}
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_HOSTSPECIALPORT) == 0 && getpid() == 1) {
			if (which_port > HOST_MAX_SPECIAL_KERNEL_PORT) {
				job_assumes(ms->job, (errno = host_set_special_port(mhp, which_port, ms->port)) == KERN_SUCCESS);
			} else {
				job_log(ms->job, LOG_WARNING, "Tried to set a reserved host special port: %d", which_port);
			}
		}
	case LAUNCH_DATA_BOOL:
		b = launch_data_get_bool(obj);
		if (strcasecmp(key, LAUNCH_JOBKEY_MACH_RESETATCLOSE) == 0) {
			ms->reset = b;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_HIDEUNTILCHECKIN) == 0) {
			ms->hide = b;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_EXCEPTIONSERVER) == 0) {
			job_assumes(ms->job, task_set_exception_ports(mts, em, ms->port,
						EXCEPTION_STATE_IDENTITY, f) == KERN_SUCCESS);
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_KUNCSERVER) == 0) {
			ms->kUNCServer = b;
			job_assumes(ms->job, host_set_UNDServer(mhp, ms->port) == KERN_SUCCESS);
		}
		break;
	default:
		break;
	}

	job_assumes(ms->job, launchd_mport_deallocate(mhp) == KERN_SUCCESS);
}

void
machservice_setup(launch_data_t obj, const char *key, void *context)
{
	job_t j = context;
	struct machservice *ms;
	mach_port_t p = MACH_PORT_NULL;

	if ((ms = job_lookup_service(j->parent, key, false))) {
		job_log(j, LOG_WARNING, "Conflict with job: %s over Mach service: %s", ms->job->label, key);
		return;
	}

	if ((ms = machservice_new(j, key, &p)) == NULL) {
		job_log_error(j, LOG_WARNING, "Cannot add service: %s", key);
		return;
	}

	ms->isActive = false;

	if (launch_data_get_type(obj) == LAUNCH_DATA_DICTIONARY) {
		launch_data_dict_iterate(obj, machservice_setup_options, ms);
	}
}

job_t 
job_parent(job_t j)
{
	return j->parent;
}

void
job_uncork_fork(job_t j)
{
	pid_t c = j->p;

	if (j->stall_before_exec) {
		job_log(j, LOG_DEBUG, "Uncorking the fork().");
		/* this unblocks the child and avoids a race
		 * between the above fork() and the kevent_mod() */
		write(j->execfd, &c, sizeof(c));
		j->stall_before_exec = false;
	} else {
		job_log(j, LOG_WARNING, "Attempt to uncork a job that isn't in the middle of a fork().");
	}
}

void
job_foreach_service(job_t j, void (*bs_iter)(struct machservice *, void *), void *context, bool only_anonymous)
{
	struct machservice *ms;
	job_t ji;

	j = job_get_bs(j);

	SLIST_FOREACH(ji, &j->jobs, sle) {
		if (ji->req_port) {
			continue;
		} else if (only_anonymous && !ji->anonymous) {
			continue;
		}

		SLIST_FOREACH(ms, &ji->machservices, sle) {
			bs_iter(ms, context);
		}
	}

	if (!job_assumes(j, SLIST_EMPTY(&j->machservices))) {
		SLIST_FOREACH(ms, &j->machservices, sle) {
			bs_iter(ms, context);
		}
	}
}

job_t 
job_new_bootstrap(job_t p, mach_port_t requestorport, mach_port_t checkin_port)
{
	char bslabel[1024] = "100000";
	mach_msg_size_t mxmsgsz;
	job_t j;

	if (requestorport == MACH_PORT_NULL) {
		if (p) {
			job_log(p, LOG_ERR, "Mach sub-bootstrap create request requires a requester port");
		}
		return NULL;
	}

	j = job_new(p, bslabel, NULL, NULL, NULL, requestorport);
	
	if (j == NULL) {
		return NULL;
	}

	if (checkin_port != MACH_PORT_NULL) {
		j->bs_port = checkin_port;
	} else if (!job_assumes(j, launchd_mport_create_recv(&j->bs_port) == KERN_SUCCESS)) {
		goto out_bad;
	}

	snprintf(j->label, strlen(j->label) + 1, "%d", MACH_PORT_INDEX(j->bs_port));

	/* Sigh... at the moment, MIG has maxsize == sizeof(reply union) */
	mxmsgsz = sizeof(union __RequestUnion__job_mig_protocol_vproc_subsystem);
	if (job_mig_protocol_vproc_subsystem.maxsize > mxmsgsz) {
		mxmsgsz = job_mig_protocol_vproc_subsystem.maxsize;
	}

	if (!job_assumes(j, runtime_add_mport(j->bs_port, protocol_vproc_server, mxmsgsz) == KERN_SUCCESS)) {
		goto out_bad;
	}

	if (p) {
		job_log(p, LOG_DEBUG, "Mach sub-bootstrap created: %s", j->label);
	}

	job_assumes(j, job_new_anonymous(j));

	return j;

out_bad:
	if (j) {
		job_remove(j);
	}
	return NULL;
}

void
job_delete_anything_with_port(job_t j, mach_port_t port)
{
	struct machservice *ms, *next_ms;
	job_t ji, jn;

	/* Mach ports, unlike Unix descriptors, are reference counted. In other
	 * words, when some program hands us a second or subsequent send right
	 * to a port we already have open, the Mach kernel gives us the same
	 * port number back and increments an reference count associated with
	 * the port. This forces us, when discovering that a receive right at
	 * the other end has been deleted, to wander all of our objects to see
	 * what weird places clients might have handed us the same send right
	 * to use.
	 */

	SLIST_FOREACH_SAFE(ji, &j->jobs, sle, jn) {
		job_delete_anything_with_port(ji, port);
	}

	SLIST_FOREACH_SAFE(ms, &j->machservices, sle, next_ms) {
		if (ms->port == port) {
			machservice_delete(ms);
		}
	}

	if (j->req_port == port) {
		if (j == root_job) {
			launchd_shutdown();
		} else {
			return job_remove(j);
		}
	}
}

struct machservice *
job_lookup_service(job_t j, const char *name, bool check_parent)
{
	struct machservice *ms;
	job_t ji;

	j = job_get_bs(j);

	SLIST_FOREACH(ji, &j->jobs, sle) {
		if (ji->req_port) {
			continue;
		}

		SLIST_FOREACH(ms, &ji->machservices, sle) {
			if (strcmp(name, ms->name) == 0) {
				if (ji->parent) {
					SLIST_REMOVE(&ji->parent->jobs, ji, job_s, sle);
					SLIST_INSERT_HEAD(&ji->parent->jobs, ji, sle);
				}
				return ms;
			}
		}
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		if (strcmp(name, ms->name) == 0) {
			return ms;
		}
	}

	if (j->parent == NULL) {
		return NULL;
	}

	if (!check_parent) {
		return NULL;
	}

	return job_lookup_service(j->parent, name, true);
}

mach_port_t
machservice_port(struct machservice *ms)
{
	return ms->port;
}

job_t 
machservice_job(struct machservice *ms)
{
	return ms->job;
}

bool
machservice_hidden(struct machservice *ms)
{
	return ms->hide;
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

void
machservice_delete(struct machservice *ms)
{
	if (ms->recv) {
		if (ms->isActive) {
			/* FIXME we should cancel the notification */
			job_log(ms->job, LOG_ERR, "Mach service deleted while we didn't own the receive right: %s", ms->name);
		} else {
			job_assumes(ms->job, launchd_mport_close_recv(ms->port) == KERN_SUCCESS);
		}
	}

	job_assumes(ms->job, launchd_mport_deallocate(ms->port) == KERN_SUCCESS);

	job_log(ms->job, LOG_INFO, "Mach service deleted: %s", ms->name);

	SLIST_REMOVE(&ms->job->machservices, ms, machservice, sle);

	free(ms);
}

void
machservice_watch(struct machservice *ms)
{
	mach_msg_id_t which = MACH_NOTIFY_DEAD_NAME;

	ms->isActive = true;

	if (ms->recv) {
		which = MACH_NOTIFY_PORT_DESTROYED;
		job_checkin(ms->job);
	}

	job_assumes(ms->job, launchd_mport_notify_req(ms->port, which) == KERN_SUCCESS);
}

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
		if (nargs < NELEM(argv)) {
			argv[nargs++] = argp;
		}
		while (*cp && (term ? *cp != term : !isspace(*cp)) && argp < END_OF(args)) {
			if (*cp == '\\') {
				cp++;
			}
			*argp++ = *cp;
			if (*cp) {
				cp++;
			}
		}
		*argp++ = '\0';
	}
	argv[nargs] = NULL;

	if (nargs == 0) {
		return NULL;
	}

	argv_ret = malloc((nargs + 1) * sizeof(char *) + strlen(string) + 1);

	if (!launchd_assumes(argv_ret != NULL)) {
		return NULL;
	}

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
job_checkin(job_t j)
{
	j->checkedin = true;
}

bool
job_ack_port_destruction(job_t j, mach_port_t p)
{
	job_t ji;
	struct machservice *ms;

	SLIST_FOREACH(ji, &j->jobs, sle) {
		if (job_ack_port_destruction(ji, p)) {
			return true;
		}
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		if (ms->port == p) {
			break;
		}
	}

	if (ms == NULL) {
		return false;
	}

	ms->isActive = false;

	if (ms->reset) {
		machservice_resetport(j, ms);
	}

	job_log(j, LOG_DEBUG, "Receive right returned to us: %s", ms->name);

	job_dispatch(j, false);

	return true;
}

void
job_ack_no_senders(job_t j)
{
	j->priv_port_has_senders = false;

	job_assumes(j, launchd_mport_close_recv(j->bs_port) == KERN_SUCCESS);
	j->bs_port = 0;

	job_log(j, LOG_DEBUG, "No more senders on privileged Mach bootstrap port");

	job_dispatch(j, false);
}

mach_port_t
job_get_reqport(job_t j)
{
	j->transfer_bstrap = true;
	gc_this_job = j;

	return j->req_port;
}

mach_port_t
job_get_bsport(job_t j)
{
	return j->bs_port;
}

job_t 
job_get_bs(job_t j)
{
	if (j->req_port) {
		return j;
	}

	if (job_assumes(j, j->parent != NULL)) {
		return j->parent;
	}

	return NULL;
}

pid_t
job_get_pid(job_t j)
{
	return j->p;
}

void
job_force_sampletool(job_t j)
{
	char pidstr[100];
	pid_t sp;
	
	snprintf(pidstr, sizeof(pidstr), "%u", j->p);

	switch ((sp = fork())) {
	case -1:
		job_log_error(j, LOG_DEBUG, "Failed to spawn sample tool");
		break;
	case 0:
		job_assumes(j, execlp("sample", "sample", pidstr, "1", "-mayDie", NULL) != -1);
		_exit(EXIT_FAILURE);
	default:
		job_assumes(j, kevent_mod(sp, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, &kqsimple_zombie_reaper) != -1);
		break;
	}
}

bool
semaphoreitem_new(job_t j, semaphore_reason_t why, const char *what)
{
	struct semaphoreitem *si;
	size_t alloc_sz = sizeof(struct semaphoreitem);

	if (what) {
		alloc_sz += strlen(what) + 1;
	}

	if (!job_assumes(j, si = calloc(1, alloc_sz))) {
		return false;
	}

	si->why = why;

	if (what) {
		strcpy(si->what, what);
	}

	SLIST_INSERT_HEAD(&j->semaphores, si, sle);

	return true;
}

void
semaphoreitem_delete(job_t j, struct semaphoreitem *ri)
{
	SLIST_REMOVE(&j->semaphores, ri, semaphoreitem, sle);

	free(ri);
}

void
semaphoreitem_setup_paths(launch_data_t obj, const char *key, void *context)
{
	job_t j = context;
	semaphore_reason_t why;

	why = launch_data_get_bool(obj) ? PATH_EXISTS : PATH_MISSING;

	semaphoreitem_new(j, why, key);
}

void
semaphoreitem_setup(launch_data_t obj, const char *key, void *context)
{
	job_t j = context;
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
job_dispatch_all_other_semaphores(job_t j, job_t nj)
{
	job_t ji, jn;

	if (j == nj) {
		return;
	}

	SLIST_FOREACH_SAFE(ji, &j->jobs, sle, jn) {
		job_dispatch_all_other_semaphores(ji, nj);
	}

	if (!SLIST_EMPTY(&j->semaphores)) {
		job_dispatch(j, false);
	}
}

time_t
cronemu(int mon, int mday, int hour, int min)
{
	struct tm workingtm;
	time_t now;

	now = time(NULL);
	workingtm = *localtime(&now);

	workingtm.tm_isdst = -1;
	workingtm.tm_sec = 0;
	workingtm.tm_min++;

	while (!cronemu_mon(&workingtm, mon, mday, hour, min)) {
		workingtm.tm_year++;
		workingtm.tm_mon = 0;
		workingtm.tm_mday = 1;
		workingtm.tm_hour = 0;
		workingtm.tm_min = 0;
		mktime(&workingtm);
	}

	return mktime(&workingtm);
}

time_t
cronemu_wday(int wday, int hour, int min)
{
	struct tm workingtm;
	time_t now;

	now = time(NULL);
	workingtm = *localtime(&now);

	workingtm.tm_isdst = -1;
	workingtm.tm_sec = 0;
	workingtm.tm_min++;

	if (wday == 7) {
		wday = 0;
	}

	while (!(workingtm.tm_wday == wday && cronemu_hour(&workingtm, hour, min))) {
		workingtm.tm_mday++;
		workingtm.tm_hour = 0;
		workingtm.tm_min = 0;
		mktime(&workingtm);
	}

	return mktime(&workingtm);
}

bool
cronemu_mon(struct tm *wtm, int mon, int mday, int hour, int min)
{
	if (mon == -1) {
		struct tm workingtm = *wtm;
		int carrytest;

		while (!cronemu_mday(&workingtm, mday, hour, min)) {
			workingtm.tm_mon++;
			workingtm.tm_mday = 1;
			workingtm.tm_hour = 0;
			workingtm.tm_min = 0;
			carrytest = workingtm.tm_mon;
			mktime(&workingtm);
			if (carrytest != workingtm.tm_mon) {
				return false;
			}
		}
		*wtm = workingtm;
		return true;
	}

        if (mon < wtm->tm_mon) {
		return false;
	}

        if (mon > wtm->tm_mon) {
		wtm->tm_mon = mon;
		wtm->tm_mday = 1;
		wtm->tm_hour = 0;
		wtm->tm_min = 0;
	}

	return cronemu_mday(wtm, mday, hour, min);
}

bool
cronemu_mday(struct tm *wtm, int mday, int hour, int min)
{
	if (mday == -1) {
		struct tm workingtm = *wtm;
		int carrytest;

		while (!cronemu_hour(&workingtm, hour, min)) {
			workingtm.tm_mday++;
			workingtm.tm_hour = 0;
			workingtm.tm_min = 0;
			carrytest = workingtm.tm_mday;
			mktime(&workingtm);
			if (carrytest != workingtm.tm_mday) {
				return false;
			}
		}
		*wtm = workingtm;
		return true;
	}

        if (mday < wtm->tm_mday) {
		return false;
	}

        if (mday > wtm->tm_mday) {
		wtm->tm_mday = mday;
		wtm->tm_hour = 0;
		wtm->tm_min = 0;
	}

	return cronemu_hour(wtm, hour, min);
}

bool
cronemu_hour(struct tm *wtm, int hour, int min)
{
	if (hour == -1) {
		struct tm workingtm = *wtm;
		int carrytest;

		while (!cronemu_min(&workingtm, min)) {
			workingtm.tm_hour++;
			workingtm.tm_min = 0;
			carrytest = workingtm.tm_hour;
			mktime(&workingtm);
			if (carrytest != workingtm.tm_hour) {
				return false;
			}
		}
		*wtm = workingtm;
		return true;
	}

	if (hour < wtm->tm_hour) {
		return false;
	}

	if (hour > wtm->tm_hour) {
		wtm->tm_hour = hour;
		wtm->tm_min = 0;
	}

	return cronemu_min(wtm, min);
}

bool
cronemu_min(struct tm *wtm, int min)
{
	if (min == -1) {
		return true;
	}

	if (min < wtm->tm_min) {
		return false;
	}

	if (min > wtm->tm_min) {
		wtm->tm_min = min;
	}

	return true;
}

kern_return_t
job_mig_create_server(job_t j, cmd_t server_cmd, uid_t server_uid, boolean_t on_demand, mach_port_t *server_portp)
{
	struct ldcred ldc;
	job_t js;

	runtime_get_caller_creds(&ldc);

	job_log(j, LOG_DEBUG, "Server create attempt: %s", server_cmd);

#define LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	/* XXX - This code should go away once the per session launchd is integrated with the rest of the system */
	#ifdef LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	if (getpid() == 1) {
		if (ldc.euid != 0 && ldc.euid != server_uid) {
			job_log(j, LOG_WARNING, "Server create: \"%s\": Will run as UID %d, not UID %d as they told us to",
					server_cmd, ldc.euid, server_uid);
			server_uid = ldc.euid;
		}
	} else
#endif
	if (!trusted_client_check(j, &ldc)) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (server_uid != getuid()) {
		job_log(j, LOG_WARNING, "Server create: \"%s\": As UID %d, we will not be able to switch to UID %d",
				server_cmd, getuid(), server_uid);
		server_uid = getuid();
	}

	js = job_new_via_mach_init(j, server_cmd, server_uid, on_demand);

	if (js == NULL) {
		return BOOTSTRAP_NO_MEMORY;
	}

	*server_portp = job_get_bsport(js);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_get_integer(job_t j, get_set_int_key_t key, int64_t *val)
{
	kern_return_t kr = 0;

	switch (key) {
	case LAST_EXIT_STATUS:
		*val = j->last_exit_status;
		break;
	default:
		kr = 1;
		break;
	}

	return kr;
}

kern_return_t
job_mig_set_integer(job_t j, get_set_int_key_t key, int64_t val)
{
	kern_return_t kr = 0;

	switch (key) {
	case GLOBAL_ON_DEMAND:
		kr = job_set_global_on_demand(j, (bool)val) ? 0 : 1;
		break;
	default:
		kr = 1;
		break;
	}

	return kr;
}

kern_return_t
job_mig_getsocket(job_t j, name_t spr)
{
	if (!sockpath) {
		return BOOTSTRAP_NO_MEMORY;
	} else if (getpid() == 1) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	strncpy(spr, sockpath, sizeof(name_t));
	
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_log(job_t j, int pri, int err, logmsg_t msg)
{
	if ((errno = err)) {
		job_log_error(j, pri, "%s", msg);
	} else {
		job_log(j, pri, "%s", msg);
	}

	return 0;
}

kern_return_t
job_mig_lookup_per_user_context(job_t j, uid_t which_user, mach_port_t *up_cont)
{
	struct ldcred ldc;
	job_t ji, jbs = root_job;

#if 0
	jbs = job_get_bs(j);
#endif

	runtime_get_caller_creds(&ldc);

	if (ldc.uid != 0) {
		which_user = ldc.uid;
	}

	if (which_user == 0) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	*up_cont = MACH_PORT_NULL;

	SLIST_FOREACH(ji, &jbs->jobs, sle) {
		if (ji->mach_uid != which_user) {
			continue;
		}
		if (SLIST_EMPTY(&ji->machservices)) {
			continue;
		}
		if (!SLIST_FIRST(&ji->machservices)->must_match_uid) {
			continue;
		}
		break;
	}

	if (ji == NULL) {
		struct machservice *ms;
		char lbuf[1024];

		sprintf(lbuf, "com.apple.launchd.peruser.%u", which_user);

		ji = job_new(jbs, lbuf, "/sbin/launchd", NULL, NULL, 0);

		if (ji == NULL) {
			return BOOTSTRAP_NO_MEMORY;
		}

		ji->mach_uid = which_user;

		if ((ms = machservice_new(ji, lbuf, up_cont)) == NULL) {
			job_remove(ji);
			return BOOTSTRAP_NO_MEMORY;
		}

		ms->must_match_uid = true;
		ms->hide = true;

		job_dispatch(ji, false);
	}

	*up_cont = machservice_port(SLIST_FIRST(&ji->machservices));

	return 0;
}

kern_return_t
job_mig_check_in(job_t j, name_t servicename, mach_port_t *serviceportp)
{
	static pid_t last_warned_pid = 0;
	struct machservice *ms;
	struct ldcred ldc;

	runtime_get_caller_creds(&ldc);

	ms = job_lookup_service(j, servicename, true);

	if (ms == NULL) {
		job_log(j, LOG_DEBUG, "Check-in of Mach service failed. Unknown: %s", servicename);
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
	if (machservice_job(ms) != j) {
		if (last_warned_pid != ldc.pid) {
			job_log(j, LOG_NOTICE, "Check-in of Mach service failed. PID %d is not privileged: %s",
					ldc.pid, servicename);
			last_warned_pid = ldc.pid;
		}
		 return BOOTSTRAP_NOT_PRIVILEGED;
	}
	if (machservice_active(ms)) {
		job_log(j, LOG_WARNING, "Check-in of Mach service failed. Already active: %s", servicename);
		return BOOTSTRAP_SERVICE_ACTIVE;
	}

	machservice_watch(ms);

	job_log(j, LOG_INFO, "Check-in of service: %s", servicename);

	*serviceportp = machservice_port(ms);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_register(job_t j, name_t servicename, mach_port_t serviceport)
{
	struct machservice *ms;
	struct ldcred ldc;

	runtime_get_caller_creds(&ldc);

#if 0
	job_log(j, LOG_NOTICE, "bootstrap_register() is deprecated. PID: %u Service: %s", ldc.pid, servicename);
#endif

	job_log(j, LOG_DEBUG, "Mach service registration attempt: %s", servicename);

	/*
	 * From a per-user/session launchd's perspective, SecurityAgent (UID
	 * 92) is a rogue application (not our UID, not root and not a child of
	 * us). We'll have to reconcile this design friction at a later date.
	 */
	if (j->anonymous && job_get_bs(j)->parent == NULL && ldc.uid != 0 && ldc.uid != getuid() && ldc.uid != 92) {
		if (getpid() == 1) {
			return VPROC_ERR_TRY_PER_USER;
		} else {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
	}
	
	ms = job_lookup_service(j, servicename, false);

	if (ms) {
		if (machservice_job(ms) != j) {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
		if (machservice_active(ms)) {
			job_log(j, LOG_DEBUG, "Mach service registration failed. Already active: %s", servicename);
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		job_checkin(machservice_job(ms));
		machservice_delete(ms);
	}

	if (serviceport != MACH_PORT_NULL) {
		if ((ms = machservice_new(j, servicename, &serviceport))) {
			machservice_watch(ms);
		} else {
			return BOOTSTRAP_NO_MEMORY;
		}
	}

	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_look_up(job_t j, name_t servicename, mach_port_t *serviceportp, mach_msg_type_name_t *ptype)
{
	struct machservice *ms;
	struct ldcred ldc;

	runtime_get_caller_creds(&ldc);

	if (getpid() == 1 && j->anonymous && job_get_bs(j)->parent == NULL && ldc.uid != 0 && ldc.euid != 0) {
		return VPROC_ERR_TRY_PER_USER;
	}

	ms = job_lookup_service(j, servicename, true);

	if (ms && machservice_hidden(ms) && !job_active(machservice_job(ms))) {
		ms = NULL;
	} else if (ms && ms->must_match_uid) {
		ms = NULL;
	}

	if (ms) {
		launchd_assumes(machservice_port(ms) != MACH_PORT_NULL);
		job_log(j, LOG_DEBUG, "Mach service lookup (by PID %d): %s", ldc.pid, servicename);
		*serviceportp = machservice_port(ms);
		*ptype = MACH_MSG_TYPE_COPY_SEND;
		return BOOTSTRAP_SUCCESS;
	} else if (inherited_bootstrap_port != MACH_PORT_NULL) {
		job_log(j, LOG_DEBUG, "Mach service lookup (by PID %d) forwarded: %s", ldc.pid, servicename);
		*ptype = MACH_MSG_TYPE_MOVE_SEND;
		return bootstrap_look_up(inherited_bootstrap_port, servicename, serviceportp);
	} else {
		job_log(j, LOG_DEBUG, "Mach service lookup (by PID %d) failed: %s", ldc.pid, servicename);
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}
}

kern_return_t
job_mig_parent(job_t j, mach_port_t *parentport, mach_msg_type_name_t *pptype)
{
	job_log(j, LOG_DEBUG, "Requested parent bootstrap port");

	j = job_get_bs(j);

	*pptype = MACH_MSG_TYPE_MAKE_SEND;

	if (job_parent(j)) {
		*parentport = job_get_bsport(job_parent(j));
	} else if (MACH_PORT_NULL == inherited_bootstrap_port) {
		*parentport = job_get_bsport(j);
	} else {
		*pptype = MACH_MSG_TYPE_COPY_SEND;
		*parentport = inherited_bootstrap_port;
	}
	return BOOTSTRAP_SUCCESS;
}

static void
job_mig_info_countservices(struct machservice *ms, void *context)
{
	unsigned int *cnt = context;

	(*cnt)++;
}

struct x_bootstrap_info_copyservices_cb {
	name_array_t service_names;
	bootstrap_status_array_t service_actives;
	mach_port_array_t ports;
	unsigned int i;
};

static void
job_mig_info_copyservices(struct machservice *ms, void *context)
{
	struct x_bootstrap_info_copyservices_cb *info_resp = context;

	strlcpy(info_resp->service_names[info_resp->i], machservice_name(ms), sizeof(info_resp->service_names[0]));

	launchd_assumes(info_resp->service_actives || info_resp->ports);

	if (info_resp->service_actives) {
		info_resp->service_actives[info_resp->i] = machservice_status(ms);
	} else {
		info_resp->ports[info_resp->i] = machservice_port(ms);
	}
	info_resp->i++;
}

kern_return_t
job_mig_info(job_t j, name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		bootstrap_status_array_t *serviceactivesp, unsigned int *serviceactives_cnt)
{
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, 0 };
	unsigned int cnt = 0;
	job_t ji;

	for (ji = j; ji; ji = job_parent(ji))
		job_foreach_service(ji, job_mig_info_countservices, &cnt, false);

	mig_allocate((vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	if (!launchd_assumes(info_resp.service_names != NULL)) {
		goto out_bad;
	}

	mig_allocate((vm_address_t *)&info_resp.service_actives, cnt * sizeof(info_resp.service_actives[0]));
	if (!launchd_assumes(info_resp.service_actives != NULL)) {
		goto out_bad;
	}

	for (ji = j; ji; ji = job_parent(ji))
		job_foreach_service(ji, job_mig_info_copyservices, &info_resp, false);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*serviceactivesp = info_resp.service_actives;
	*servicenames_cnt = *serviceactives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names) {
		mig_deallocate((vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	}
	if (info_resp.service_actives) {
		mig_deallocate((vm_address_t)info_resp.service_actives, cnt * sizeof(info_resp.service_actives[0]));
	}

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_transfer_subset(job_t j, mach_port_t *reqport, mach_port_t *rcvright,
		name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		mach_port_array_t *ports, unsigned int *ports_cnt)
{
	struct x_bootstrap_info_copyservices_cb info_resp = { NULL, NULL, NULL, 0 };
	unsigned int cnt = 0;

	if (j->anonymous) {
		j = j->parent;
	}

	if (getpid() != 1) {
		job_log(j, LOG_ERR, "Only the system launchd will transfer Mach sub-bootstraps.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (!job_parent(j)) {
		job_log(j, LOG_ERR, "Root Mach bootstrap cannot be transferred.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	job_log(j, LOG_DEBUG, "Transferring sub-bootstrap to the per session launchd.");

	job_foreach_service(j, job_mig_info_countservices, &cnt, true);

	mig_allocate((vm_address_t *)&info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	if (!launchd_assumes(info_resp.service_names != NULL)) {
		goto out_bad;
	}

	mig_allocate((vm_address_t *)&info_resp.ports, cnt * sizeof(info_resp.ports[0]));
	if (!launchd_assumes(info_resp.ports != NULL)) {
		goto out_bad;
	}

	job_foreach_service(j, job_mig_info_copyservices, &info_resp, true);

	launchd_assumes(info_resp.i == cnt);

	*servicenamesp = info_resp.service_names;
	*ports = info_resp.ports;
	*servicenames_cnt = *ports_cnt = cnt;

	*reqport = job_get_reqport(j);
	*rcvright = job_get_bsport(j);

	launchd_assumes(runtime_remove_mport(*rcvright) == KERN_SUCCESS);

	launchd_assumes(launchd_mport_make_send(*rcvright) == KERN_SUCCESS);

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (info_resp.service_names) {
		mig_deallocate((vm_address_t)info_resp.service_names, cnt * sizeof(info_resp.service_names[0]));
	}
	if (info_resp.ports) {
		mig_deallocate((vm_address_t)info_resp.ports, cnt * sizeof(info_resp.ports[0]));
	}

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_subset(job_t j, mach_port_t requestorport, mach_port_t *subsetportp)
{
	int bsdepth = 0;
	job_t js = j;

	while ((js = job_parent(js)) != NULL) {
		bsdepth++;
	}

	/* Since we use recursion, we need an artificial depth for subsets */
	if (bsdepth > 100) {
		job_log(j, LOG_ERR, "Mach sub-bootstrap create request failed. Depth greater than: %d", bsdepth);
		return BOOTSTRAP_NO_MEMORY;
	}

	if ((js = job_new_bootstrap(j, requestorport, MACH_PORT_NULL)) == NULL) {
		if (requestorport == MACH_PORT_NULL) {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
		return BOOTSTRAP_NO_MEMORY;
	}

	*subsetportp = job_get_bsport(js);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_create_service(job_t j, name_t servicename, mach_port_t *serviceportp)
{
	struct machservice *ms;

	if (job_prog(j)[0] == '\0') {
		job_log(j, LOG_ERR, "Mach service creation requires a target server: %s", servicename);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (!j->legacy_mach_job) {
		job_log(j, LOG_ERR, "bootstrap_create_service() is only allowed against legacy Mach jobs: %s", servicename);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	ms = job_lookup_service(j, servicename, false);
	if (ms) {
		job_log(j, LOG_DEBUG, "Mach service creation attempt for failed. Already exists: %s", servicename);
		return BOOTSTRAP_NAME_IN_USE;
	}

	job_checkin(j);

	*serviceportp = MACH_PORT_NULL;
	ms = machservice_new(j, servicename, serviceportp);

	if (!launchd_assumes(ms != NULL)) {
		goto out_bad;
	}

	return BOOTSTRAP_SUCCESS;

out_bad:
	launchd_assumes(launchd_mport_close_recv(*serviceportp) == KERN_SUCCESS);
	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_wait(job_t j, mach_port_t srp, integer_t *waitstatus)
{
#if 0
	struct ldcred ldc;
	runtime_get_caller_creds(&ldc);
#endif
	return job_handle_mpm_wait(j, srp, waitstatus);
}

kern_return_t
job_mig_uncork_fork(job_t j)
{
	if (!j) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	job_uncork_fork(j);

	return 0;
}

kern_return_t
job_mig_spawn(job_t j, _internal_string_t charbuf, mach_msg_type_number_t charbuf_cnt,
		uint32_t argc, uint32_t envc, uint64_t flags, uint16_t mig_umask,
		pid_t *child_pid, mach_port_t *obsvr_port)
{
	job_t jr;
	struct ldcred ldc;
	size_t offset = 0;
	char *tmpp;
	const char **argv = NULL, **env = NULL;
	const char *label = NULL;
	const char *path = NULL;
	const char *workingdir = NULL;
	size_t argv_i = 0, env_i = 0;

	runtime_get_caller_creds(&ldc);

#if 0
	if (ldc.asid != inherited_asid) {
		job_log(j, LOG_ERR, "Security: PID %d (ASID %d) was denied a request to spawn a process in this session (ASID %d)",
				ldc.pid, ldc.asid, inherited_asid);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}
#endif

	argv = alloca((argc + 1) * sizeof(char *));
	memset(argv, 0, (argc + 1) * sizeof(char *));

	if (envc > 0) {
		env = alloca((envc + 1) * sizeof(char *));
		memset(env, 0, (envc + 1) * sizeof(char *));
	}

	while (offset < charbuf_cnt) {
		tmpp = charbuf + offset;
		offset += strlen(tmpp) + 1;
		if (!label) {
			label = tmpp;
		} else if (argc > 0) {
			argv[argv_i] = tmpp;
			argv_i++;
			argc--;
		} else if (envc > 0) {
			env[env_i] = tmpp;
			env_i++;
			envc--;
		} else if (flags & SPAWN_HAS_PATH) {
			path = tmpp;
			flags &= ~SPAWN_HAS_PATH;
		} else if (flags & SPAWN_HAS_WDIR) {
			workingdir = tmpp;
			flags &= ~SPAWN_HAS_WDIR;
		}
	}

	jr = job_new_spawn(job_get_bs(j), label, path, workingdir, argv, env, flags & SPAWN_HAS_UMASK ? &mig_umask : NULL,
			flags & SPAWN_WANTS_WAIT4DEBUGGER, flags & SPAWN_WANTS_FORCE_PPC);

	if (jr == NULL) switch (errno) {
	case EEXIST:
		return BOOTSTRAP_NAME_IN_USE;
	default:
		return BOOTSTRAP_NO_MEMORY;
	}

	if (getuid() == 0) {
		jr->mach_uid = ldc.uid;
	}

	if (!job_setup_machport(jr)) {
		job_remove(jr);
		return BOOTSTRAP_NO_MEMORY;
	}

	job_log(j, LOG_INFO, "Spawned with flags:%s%s",
			flags & SPAWN_WANTS_FORCE_PPC ? " ppc": "",
			flags & SPAWN_WANTS_WAIT4DEBUGGER ? " stopped": "");

	*child_pid = job_get_pid(jr);
	*obsvr_port = job_get_bsport(jr);

	return BOOTSTRAP_SUCCESS;
}

bool
trusted_client_check(job_t j, struct ldcred *ldc)
{
	static pid_t last_warned_pid = 0;

	/*
	 * In the long run, we wish to enforce the progeny rule, but for now,
	 * we'll let root and the user be forgiven. Once we get CoreProcesses
	 * to switch to using launchd rather than the WindowServer for indirect
	 * process invocation, we can then seriously look at cranking up the
	 * warning level here.
	 */

	if (inherited_asid == ldc->asid) {
		return true;
	}
	if (progeny_check(ldc->pid)) {
		return true;
	}
	if (ldc->euid == geteuid()) {
		return true;
	}
	if (ldc->euid == 0 && ldc->uid == 0) {
		return true;
	}
	if (last_warned_pid == ldc->pid) {
		return false;
	}

	job_log(j, LOG_NOTICE, "Security: PID %d (ASID %d) was leaked into this session (ASID %d). This will be denied in the future.", ldc->pid, ldc->asid, inherited_asid);

	last_warned_pid = ldc->pid;

	return false;
}

void
mach_init_init(mach_port_t req_port, mach_port_t checkin_port,
		name_array_t l2l_names, mach_port_array_t l2l_ports, mach_msg_type_number_t l2l_cnt)
{
	mach_msg_type_number_t l2l_i;
	auditinfo_t inherited_audit;
	job_t anon_job;

	getaudit(&inherited_audit);
	inherited_asid = inherited_audit.ai_asid;

	launchd_assert((root_job = job_new_bootstrap(NULL, req_port ? req_port : mach_task_self(), checkin_port)) != NULL);

	launchd_assert((anon_job = job_find_anonymous(root_job)) != NULL);

	launchd_assert(launchd_get_bport(&inherited_bootstrap_port) == KERN_SUCCESS);

	if (getpid() != 1) {
		launchd_assumes(inherited_bootstrap_port != MACH_PORT_NULL);
	}

	/* We set this explicitly as we start each child */
	launchd_assert(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);

	/* cut off the Libc cache, we don't want to deadlock against ourself */
	bootstrap_port = MACH_PORT_NULL;

	if (l2l_names == NULL) {
		return;
	}

	for (l2l_i = 0; l2l_i < l2l_cnt; l2l_i++) {
		struct machservice *ms;

		if ((ms = machservice_new(anon_job, l2l_names[l2l_i], &l2l_ports[l2l_i]))) {
			machservice_watch(ms);
		}
	}
}
