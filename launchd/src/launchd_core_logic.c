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
#include <mach/host_reboot.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/pipe.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <bsm/libbsm.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
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
#include <spawn.h>
#include <sandbox.h>

#include "liblaunch_public.h"
#include "liblaunch_private.h"
#include "liblaunch_internal.h"
#include "libbootstrap_public.h"
#include "libbootstrap_private.h"
#include "libvproc_public.h"
#include "libvproc_internal.h"

#include "reboot2.h"

#include "launchd.h"
#include "launchd_runtime.h"
#include "launchd_unix_ipc.h"
#include "protocol_vproc.h"
#include "protocol_vprocServer.h"
#include "job_reply.h"

#define LAUNCHD_MIN_JOB_RUN_TIME 10
#define LAUNCHD_ADVISABLE_IDLE_TIMEOUT 30
#define LAUNCHD_DEFAULT_EXIT_TIMEOUT 20
#define LAUNCHD_SIGKILL_TIMER 5


#define TAKE_SUBSET_NAME	"TakeSubsetName"
#define TAKE_SUBSET_PID		"TakeSubsetPID"
#define TAKE_SUBSET_PERPID	"TakeSubsetPerPID"

#define IS_POWER_OF_TWO(v)	(!(v & (v - 1)) && v)

extern char **environ;

mach_port_t inherited_bootstrap_port;

struct mspolicy {
	SLIST_ENTRY(mspolicy) sle;
	unsigned int		allow:1, per_pid:1;
	const char		name[0];
};

static bool mspolicy_new(job_t j, const char *name, bool allow, bool pid_local, bool skip_check);
static bool mspolicy_copy(job_t j_to, job_t j_from);
static void mspolicy_setup(launch_data_t obj, const char *key, void *context);
static bool mspolicy_check(job_t j, const char *name, bool pid_local);
static void mspolicy_delete(job_t j, struct mspolicy *msp);

struct machservice {
	SLIST_ENTRY(machservice) sle;
	LIST_ENTRY(machservice) name_hash_sle;
	LIST_ENTRY(machservice) port_hash_sle;
	job_t			job;
	uint64_t		bad_perf_cnt;
	unsigned int		gen_num;
	mach_port_name_t	port;
	unsigned int		isActive:1, reset:1, recv:1, hide:1, kUNCServer:1, per_user_hack:1, debug_on_close:1, per_pid:1;
	const char		name[0];
};

#define PORT_HASH_SIZE 32
#define HASH_PORT(x)	(IS_POWER_OF_TWO(PORT_HASH_SIZE) ? (MACH_PORT_INDEX(x) & (PORT_HASH_SIZE - 1)) : (MACH_PORT_INDEX(x) % PORT_HASH_SIZE))

static LIST_HEAD(, machservice) port_hash[PORT_HASH_SIZE];

static void machservice_setup(launch_data_t obj, const char *key, void *context);
static void machservice_setup_options(launch_data_t obj, const char *key, void *context);
static void machservice_resetport(job_t j, struct machservice *ms);
static struct machservice *machservice_new(job_t j, const char *name, mach_port_t *serviceport, bool pid_local);
static void machservice_ignore(job_t j, struct machservice *ms);
static void machservice_watch(job_t j, struct machservice *ms);
static void machservice_delete(job_t j, struct machservice *, bool port_died);
static void machservice_request_notifications(struct machservice *);
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
static void socketgroup_callback(job_t j);
static void socketgroup_setup(launch_data_t obj, const char *key, void *context);

struct calendarinterval {
	LIST_ENTRY(calendarinterval) global_sle;
	SLIST_ENTRY(calendarinterval) sle;
	job_t job;
	struct tm when;
	time_t when_next;
};

static LIST_HEAD(, calendarinterval) sorted_calendar_events;

static bool calendarinterval_new(job_t j, struct tm *w);
static bool calendarinterval_new_from_obj(job_t j, launch_data_t obj);
static void calendarinterval_delete(job_t j, struct calendarinterval *ci);
static void calendarinterval_setalarm(job_t j, struct calendarinterval *ci);
static void calendarinterval_callback(void);
static void calendarinterval_sanity_check(void);

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
static void seatbelt_setup_flags(launch_data_t obj, const char *key, void *context);

typedef enum {
	NETWORK_UP = 1,
	NETWORK_DOWN,
	SUCCESSFUL_EXIT,
	FAILED_EXIT,
	PATH_EXISTS,
	PATH_MISSING,
	OTHER_JOB_ENABLED,
	OTHER_JOB_DISABLED,
	OTHER_JOB_ACTIVE,
	OTHER_JOB_INACTIVE,
	PATH_CHANGES,
	DIR_NOT_EMPTY,
	// FILESYSTEMTYPE_IS_MOUNTED,	/* for nfsiod, but maybe others */
} semaphore_reason_t;

struct semaphoreitem {
	SLIST_ENTRY(semaphoreitem) sle;
	semaphore_reason_t why;
	int fd;
	char what[0];
};

struct semaphoreitem_dict_iter_context {
	job_t j;
	semaphore_reason_t why_true;
	semaphore_reason_t why_false;
};

static bool semaphoreitem_new(job_t j, semaphore_reason_t why, const char *what);
static void semaphoreitem_delete(job_t j, struct semaphoreitem *si);
static void semaphoreitem_setup(launch_data_t obj, const char *key, void *context);
static void semaphoreitem_setup_dict_iter(launch_data_t obj, const char *key, void *context);
static void semaphoreitem_callback(job_t j, struct kevent *kev);
static void semaphoreitem_watch(job_t j, struct semaphoreitem *si);
static void semaphoreitem_ignore(job_t j, struct semaphoreitem *si);

#define ACTIVE_JOB_HASH_SIZE	32
#define ACTIVE_JOB_HASH(x)	(IS_POWER_OF_TWO(ACTIVE_JOB_HASH_SIZE) ? (x & (ACTIVE_JOB_HASH_SIZE - 1)) : (x % ACTIVE_JOB_HASH_SIZE))
#define MACHSERVICE_HASH_SIZE	37

struct jobmgr_s {
	kq_callback kqjobmgr_callback;
	SLIST_ENTRY(jobmgr_s) sle;
	SLIST_HEAD(, jobmgr_s) submgrs;
	LIST_HEAD(, job_s) jobs;
	LIST_HEAD(, job_s) active_jobs[ACTIVE_JOB_HASH_SIZE];
	LIST_HEAD(, machservice) ms_hash[MACHSERVICE_HASH_SIZE];
	mach_port_t jm_port;
	mach_port_t req_port;
	jobmgr_t parentmgr;
	int reboot_flags;
	unsigned int global_on_demand_cnt;
	unsigned int hopefully_first_cnt;
	unsigned int normal_active_cnt;
	unsigned int sent_stop_to_normal_jobs:1, sent_stop_to_hopefully_last_jobs:1, shutting_down:1, session_initialized:1;
	char name[0];
};

#define jobmgr_assumes(jm, e)      \
	                (__builtin_expect(!(e), 0) ? jobmgr_log_bug(jm, __rcs_file_version__, __FILE__, __LINE__, #e), false : true)

static jobmgr_t jobmgr_new(jobmgr_t jm, mach_port_t requestorport, mach_port_t transfer_port, bool sflag, const char *name);
static job_t jobmgr_import2(jobmgr_t jm, launch_data_t pload);
static jobmgr_t jobmgr_parent(jobmgr_t jm);
static jobmgr_t jobmgr_do_garbage_collection(jobmgr_t jm);
static void jobmgr_reap_bulk(jobmgr_t jm, struct kevent *kev);
static void jobmgr_log_stray_children(jobmgr_t jm);
static void jobmgr_remove(jobmgr_t jm);
static void jobmgr_dispatch_all(jobmgr_t jm, bool newmounthack);
static job_t jobmgr_init_session(jobmgr_t jm, const char *session_type, bool sflag);
static job_t jobmgr_find_by_pid(jobmgr_t jm, pid_t p, bool create_anon);
static job_t job_mig_intran2(jobmgr_t jm, mach_port_t mport, pid_t upid);
static void job_export_all2(jobmgr_t jm, launch_data_t where);
static void jobmgr_callback(void *obj, struct kevent *kev);
static void jobmgr_setup_env_from_other_jobs(jobmgr_t jm);
static void jobmgr_export_env_from_other_jobs(jobmgr_t jm, launch_data_t dict);
static struct machservice *jobmgr_lookup_service(jobmgr_t jm, const char *name, bool check_parent, pid_t target_pid);
static void jobmgr_logv(jobmgr_t jm, int pri, int err, const char *msg, va_list ap) __attribute__((format(printf, 4, 0)));
static void jobmgr_log(jobmgr_t jm, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
/* static void jobmgr_log_error(jobmgr_t jm, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4))); */
static void jobmgr_log_bug(jobmgr_t jm, const char *rcs_rev, const char *path, unsigned int line, const char *test);

#define DO_RUSAGE_SUMMATION 0

#define AUTO_PICK_LEGACY_LABEL (const char *)(~0)

struct job_s {
	kq_callback kqjob_callback;
	LIST_ENTRY(job_s) sle;
	LIST_ENTRY(job_s) pid_hash_sle;
	LIST_ENTRY(job_s) label_hash_sle;
	SLIST_HEAD(, socketgroup) sockets;
	SLIST_HEAD(, calendarinterval) cal_intervals;
	SLIST_HEAD(, envitem) global_env;
	SLIST_HEAD(, envitem) env;
	SLIST_HEAD(, limititem) limits;
	SLIST_HEAD(, mspolicy) mspolicies;
	SLIST_HEAD(, machservice) machservices;
	SLIST_HEAD(, semaphoreitem) semaphores;
#if DO_RUSAGE_SUMMATION
	struct rusage ru;
#endif
	cpu_type_t *j_binpref;
	size_t j_binpref_cnt;
	mach_port_t j_port;
	mach_port_t wait_reply_port;
	uid_t mach_uid;
	jobmgr_t mgr;
	char **argv;
	char *prog;
	char *rootdir;
	char *workingdir;
	char *username;
	char *groupname;
	char *stdoutpath;
	char *stderrpath;
	struct machservice *lastlookup;
	unsigned int lastlookup_gennum;
	char *seatbelt_profile;
	uint64_t seatbelt_flags;
	void *quarantine_data;
	size_t quarantine_data_sz;
	pid_t p;
	int argc;
	int last_exit_status;
	int forkfd;
	int log_redirect_fd;
	int nice;
	unsigned int timeout;
	unsigned int exit_timeout;
	int stdout_err_fd;
	struct timeval sent_sigterm_time;
	time_t start_time;
	time_t min_run_time;
	unsigned int start_interval;
	unsigned int checkedin:1, anonymous:1, debug:1, inetcompat:1, inetcompat_wait:1,
		     ondemand:1, session_create:1, low_pri_io:1, no_init_groups:1, priv_port_has_senders:1,
		     importing_global_env:1, importing_hard_limits:1, setmask:1, legacy_mach_job:1, start_pending:1;
	mode_t mask;
	unsigned int globargv:1, wait4debugger:1, unload_at_exit:1, stall_before_exec:1, only_once:1,
		     currently_ignored:1, forced_peers_to_demand_mode:1, setnice:1, hopefully_exits_last:1, removal_pending:1,
		     wait4pipe_eof:1, sent_sigkill:1, debug_before_kill:1, weird_bootstrap:1, start_on_mount:1,
		     per_user:1, hopefully_exits_first:1, deny_unknown_mslookups:1, unload_at_mig_return:1;
	const char label[0];
};

#define LABEL_HASH_SIZE 53

static LIST_HEAD(, job_s) label_hash[LABEL_HASH_SIZE];
static size_t hash_label(const char *label) __attribute__((pure));
static size_t hash_ms(const char *msstr) __attribute__((pure));


#define job_assumes(j, e)      \
	                (__builtin_expect(!(e), 0) ? job_log_bug(j, __rcs_file_version__, __FILE__, __LINE__, #e), false : true)

static void job_import_keys(launch_data_t obj, const char *key, void *context);
static void job_import_bool(job_t j, const char *key, bool value);
static void job_import_string(job_t j, const char *key, const char *value);
static void job_import_integer(job_t j, const char *key, long long value);
static void job_import_dictionary(job_t j, const char *key, launch_data_t value);
static void job_import_array(job_t j, const char *key, launch_data_t value);
static void job_import_opaque(job_t j, const char *key, launch_data_t value);
static bool job_set_global_on_demand(job_t j, bool val);
static void job_watch(job_t j);
static void job_ignore(job_t j);
static void job_reap(job_t j);
static bool job_useless(job_t j);
static bool job_keepalive(job_t j);
static void job_start(job_t j);
static void job_start_child(job_t j) __attribute__((noreturn));
static void job_setup_attributes(job_t j);
static bool job_setup_machport(job_t j);
static void job_setup_fd(job_t j, int target_fd, const char *path, int flags);
static void job_postfork_become_user(job_t j);
static void job_find_and_blame_pids_with_weird_uids(job_t j);
static void job_force_sampletool(job_t j);
static void job_setup_exception_port(job_t j, task_t target_task);
static void job_reparent_hack(job_t j, const char *where);
static void job_callback(void *obj, struct kevent *kev);
static void job_callback_proc(job_t j, int flags, int fflags);
static void job_callback_timer(job_t j, void *ident);
static void job_callback_read(job_t j, int ident);
static job_t job_new_anonymous(jobmgr_t jm, pid_t anonpid);
static job_t job_new(jobmgr_t jm, const char *label, const char *prog, const char *const *argv);
static job_t job_new_via_mach_init(job_t j, const char *cmd, uid_t uid, bool ond);
static const char *job_prog(job_t j);
static pid_t job_get_pid(job_t j);
static jobmgr_t job_get_bs(job_t j);
static void job_kill(job_t j);
static void job_uncork_fork(job_t j);
static void job_log_stdouterr(job_t j);
static void job_logv(job_t j, int pri, int err, const char *msg, va_list ap) __attribute__((format(printf, 4, 0)));
static void job_log_error(job_t j, int pri, const char *msg, ...) __attribute__((format(printf, 3, 4)));
static void job_log_bug(job_t j, const char *rcs_rev, const char *path, unsigned int line, const char *test);
static void job_set_exeception_port(job_t j, mach_port_t port);
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

static unsigned int total_children;
static void ensure_root_bkgd_setup(void);
static int dir_has_files(job_t j, const char *path);
static char **mach_cmd2argv(const char *string);
static size_t our_strhash(const char *s) __attribute__((pure));
static mach_port_t the_exception_server;
static bool did_first_per_user_launchd_BootCache_hack;

jobmgr_t root_jobmgr;
static jobmgr_t background_jobmgr;

void
job_ignore(job_t j)
{
	struct semaphoreitem *si;
	struct socketgroup *sg;
	struct machservice *ms;

	if (j->currently_ignored) {
		return;
	}

	job_log(j, LOG_DEBUG, "Ignoring...");

	j->currently_ignored = true;

	SLIST_FOREACH(sg, &j->sockets, sle) {
		socketgroup_ignore(j, sg);
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		machservice_ignore(j, ms);
	}

	SLIST_FOREACH(si, &j->semaphores, sle) {
		semaphoreitem_ignore(j, si);
	}
}

void
job_watch(job_t j)
{
	struct semaphoreitem *si;
	struct socketgroup *sg;
	struct machservice *ms;

	if (!j->currently_ignored) {
		return;
	}

	job_log(j, LOG_DEBUG, "Watching...");

	j->currently_ignored = false;

	SLIST_FOREACH(sg, &j->sockets, sle) {
		socketgroup_watch(j, sg);
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		machservice_watch(j, ms);
	}

	SLIST_FOREACH(si, &j->semaphores, sle) {
		semaphoreitem_watch(j, si);
	}
}

void
job_stop(job_t j)
{
	if (!j->p || j->anonymous) {
		return;
	}

	job_assumes(j, kill(j->p, SIGTERM) != -1);
	job_assumes(j, gettimeofday(&j->sent_sigterm_time, NULL) != -1);

	if (j->exit_timeout) {
		job_assumes(j, kevent_mod((uintptr_t)&j->exit_timeout, EVFILT_TIMER,
					EV_ADD|EV_ONESHOT, NOTE_SECONDS, j->exit_timeout, j) != -1);
	}
}

launch_data_t
job_export(job_t j)
{
	launch_data_t tmp, tmp2, tmp3, r = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (r == NULL) {
		return NULL;
	}

	if ((tmp = launch_data_new_string(j->label))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LABEL);
	}
	if ((tmp = launch_data_new_string(j->mgr->name))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE);
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

	if (j->session_create && (tmp = launch_data_new_bool(true))) {
		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_SESSIONCREATE);
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
			if (sg->junkfds) {
				continue;
			}
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
		
		tmp3 = NULL;

		SLIST_FOREACH(ms, &j->machservices, sle) {
			if (ms->per_pid) {
				if (tmp3 == NULL) {
					tmp3 = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
				}
				if (tmp3) {
					tmp2 = launch_data_new_machport(MACH_PORT_NULL);
					launch_data_dict_insert(tmp3, tmp2, ms->name);
				}
			} else {
				tmp2 = launch_data_new_machport(MACH_PORT_NULL);
				launch_data_dict_insert(tmp, tmp2, ms->name);
			}
		}

		launch_data_dict_insert(r, tmp, LAUNCH_JOBKEY_MACHSERVICES);

		if (tmp3) {
			launch_data_dict_insert(r, tmp3, LAUNCH_JOBKEY_PERJOBMACHSERVICES);
		}
	}

	return r;
}

jobmgr_t
jobmgr_shutdown(jobmgr_t jm)
{
	jobmgr_t jmi, jmn;
	job_t ji;

	jobmgr_log(jm, LOG_DEBUG, "Beginning job manager shutdown with flags: %s", reboot_flags_to_C_names(jm->reboot_flags));

	jm->shutting_down = true;

	SLIST_FOREACH_SAFE(jmi, &jm->submgrs, sle, jmn) {
		jobmgr_shutdown(jmi);
	}

	if (jm->hopefully_first_cnt) {
		LIST_FOREACH(ji, &jm->jobs, sle) {
			if (ji->p && ji->hopefully_exits_first) {
				job_stop(ji);
			}
		}
	}

	if (debug_shutdown_hangs && jm->parentmgr == NULL && getpid() == 1) {
		jobmgr_assumes(jm, kevent_mod((uintptr_t)jm, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, 3, jm) != -1);
	}

	return jobmgr_do_garbage_collection(jm);
}

void
jobmgr_remove(jobmgr_t jm)
{
	jobmgr_t jmi;
	job_t ji;

	jobmgr_log(jm, LOG_DEBUG, "Removed job manager");

	if (!jobmgr_assumes(jm, SLIST_EMPTY(&jm->submgrs))) {
		while ((jmi = SLIST_FIRST(&jm->submgrs))) {
			jobmgr_remove(jmi);
		}
	}

	while ((ji = LIST_FIRST(&jm->jobs))) {
		/* We should only have anonymous jobs left */
		job_assumes(ji, ji->anonymous);
		job_remove(ji);
	}

	if (jm->req_port) {
		jobmgr_assumes(jm, launchd_mport_deallocate(jm->req_port) == KERN_SUCCESS);
	}

	if (jm->jm_port) {
		jobmgr_assumes(jm, launchd_mport_close_recv(jm->jm_port) == KERN_SUCCESS);
	}

	if (jm == background_jobmgr) {
		background_jobmgr = NULL;
	}

	if (jm->parentmgr) {
		SLIST_REMOVE(&jm->parentmgr->submgrs, jm, jobmgr_s, sle);
	} else if (getpid() == 1) {
		jobmgr_log(jm, LOG_DEBUG, "About to call: reboot(%s)", reboot_flags_to_C_names(jm->reboot_flags));
		runtime_closelog();
		jobmgr_assumes(jm,  reboot(jm->reboot_flags) != -1);
		runtime_closelog();
	} else {
		runtime_closelog();
		jobmgr_log(jm, LOG_DEBUG, "About to exit.");
		exit(EXIT_SUCCESS);
	}
	
	free(jm);
}

void
job_remove(job_t j)
{
	struct calendarinterval *ci;
	struct semaphoreitem *si;
	struct socketgroup *sg;
	struct machservice *ms;
	struct limititem *li;
	struct mspolicy *msp;
	struct envitem *ei;

	if (j->p && j->anonymous) {
		job_reap(j);
	} else if (j->p) {
		job_log(j, LOG_DEBUG, "Removal pended until the job exits.");

		if (!j->removal_pending) {
			j->removal_pending = true;
			job_stop(j);
		}

		return;
	}

	ipc_close_all_with_job(j);

	if (j->forced_peers_to_demand_mode) {
		job_set_global_on_demand(j, false);
	}

	if (!job_assumes(j, j->forkfd == 0)) {
		job_assumes(j, runtime_close(j->forkfd) != -1);
	}

	if (!job_assumes(j, j->log_redirect_fd == 0)) {
		job_assumes(j, runtime_close(j->log_redirect_fd) != -1);
	}

	if (j->j_port) {
		job_assumes(j, launchd_mport_close_recv(j->j_port) == KERN_SUCCESS);
	}

	if (!job_assumes(j, j->wait_reply_port == MACH_PORT_NULL)) {
		job_assumes(j, launchd_mport_deallocate(j->wait_reply_port) == KERN_SUCCESS);
	}

	while ((msp = SLIST_FIRST(&j->mspolicies))) {
		mspolicy_delete(j, msp);
	}
	while ((sg = SLIST_FIRST(&j->sockets))) {
		socketgroup_delete(j, sg);
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
		machservice_delete(j, ms, false);
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
	if (j->stdoutpath) {
		free(j->stdoutpath);
	}
	if (j->stderrpath) {
		free(j->stderrpath);
	}
	if (j->seatbelt_profile) {
		free(j->seatbelt_profile);
	}
	if (j->quarantine_data) {
		free(j->quarantine_data);
	}
	if (j->j_binpref) {
		free(j->j_binpref);
	}
	if (j->start_interval) {
		job_assumes(j, kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_DELETE, 0, 0, NULL) != -1);
	}

	kevent_mod((uintptr_t)j, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	LIST_REMOVE(j, sle);
	LIST_REMOVE(j, label_hash_sle);

	job_log(j, LOG_DEBUG, "Removed");

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
		j->mgr->global_on_demand_cnt++;
	} else {
		j->mgr->global_on_demand_cnt--;
	}

	if (j->mgr->global_on_demand_cnt == 0) {
		jobmgr_dispatch_all(j->mgr, false);
	}

	return true;
}

bool
job_setup_machport(job_t j)
{
	mach_msg_size_t mxmsgsz;

	if (!job_assumes(j, launchd_mport_create_recv(&j->j_port) == KERN_SUCCESS)) {
		goto out_bad;
	}

	/* Sigh... at the moment, MIG has maxsize == sizeof(reply union) */
	mxmsgsz = sizeof(union __RequestUnion__job_mig_protocol_vproc_subsystem);
	if (job_mig_protocol_vproc_subsystem.maxsize > mxmsgsz) {
		mxmsgsz = job_mig_protocol_vproc_subsystem.maxsize;
	}

	if (!job_assumes(j, runtime_add_mport(j->j_port, protocol_vproc_server, mxmsgsz) == KERN_SUCCESS)) {
		goto out_bad2;
	}

	if (!job_assumes(j, launchd_mport_notify_req(j->j_port, MACH_NOTIFY_NO_SENDERS) == KERN_SUCCESS)) {
		job_assumes(j, launchd_mport_close_recv(j->j_port) == KERN_SUCCESS);
		goto out_bad;
	}

	return true;
out_bad2:
	job_assumes(j, launchd_mport_close_recv(j->j_port) == KERN_SUCCESS);
out_bad:
	return false;
}

job_t 
job_new_via_mach_init(job_t j, const char *cmd, uid_t uid, bool ond)
{
	const char **argv = (const char **)mach_cmd2argv(cmd);
	job_t jr = NULL;

	if (!job_assumes(j, argv != NULL)) {
		goto out_bad;
	}

	jr = job_new(j->mgr, AUTO_PICK_LEGACY_LABEL, NULL, argv);

	free(argv);

	/* jobs can easily be denied creation during shutdown */
	if (!jr) {
		goto out_bad;
	}

	jr->mach_uid = uid;
	jr->ondemand = ond;
	jr->legacy_mach_job = true;
	jr->priv_port_has_senders = true; /* the IPC that called us will make-send on this port */

	if (!job_setup_machport(jr)) {
		goto out_bad;
	}

	job_log(jr, LOG_INFO, "Legacy%s server created", ond ? " on-demand" : "");

	return jr;

out_bad:
	if (jr) {
		job_remove(jr);
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
job_new_anonymous(jobmgr_t jm, pid_t anonpid)
{
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, anonpid };
	struct kinfo_proc kp;
	size_t len = sizeof(kp);
	const char *zombie = NULL;
	bool shutdown_state;
	job_t jp = NULL, jr = NULL;

	if (!jobmgr_assumes(jm, anonpid != 0)) {
		return NULL;
	}

	if (!jobmgr_assumes(jm, sysctl(mib, 4, &kp, &len, NULL, 0) != -1)) {
		return NULL;
	}

	if (kp.kp_proc.p_stat == SZOMB) {
		jobmgr_log(jm, LOG_DEBUG, "Tried to create an anonymous job for zombie PID: %u", anonpid);
		zombie = "zombie";
	}

	switch (kp.kp_eproc.e_ppid) {
	case 0:
		/* the kernel */
		break;
	case 1:
		if (getpid() != 1) {
			break;
		}
		/* fall through */
	default:
		jp = jobmgr_find_by_pid(jm, kp.kp_eproc.e_ppid, true);
		jobmgr_assumes(jm, jp != NULL);
		break;
	}

	/* A total hack: Normally, job_new() returns an error during shutdown, but anonymous jobs are special. */
	if ((shutdown_state = jm->shutting_down)) {
		jm->shutting_down = false;
	}

	if (jobmgr_assumes(jm, (jr = job_new(jm, AUTO_PICK_LEGACY_LABEL, zombie ? zombie : kp.kp_proc.p_comm, NULL)) != NULL)) {
		u_int proc_fflags = NOTE_EXEC|NOTE_EXIT|NOTE_REAP;

		total_children++;
		jr->anonymous = true;
		jr->p = anonpid;

		/* anonymous process reaping is messy */
		LIST_INSERT_HEAD(&jm->active_jobs[ACTIVE_JOB_HASH(jr->p)], jr, pid_hash_sle);

		if (kevent_mod(jr->p, EVFILT_PROC, EV_ADD, proc_fflags, 0, root_jobmgr) == -1 && job_assumes(jr, errno == ESRCH)) {
			/* zombies are weird */
			job_log(jr, LOG_ERR, "Failed to add kevent for PID %u. Will unload at MIG return.", jr->p);
			jr->unload_at_mig_return = true;
		}

		if (jp) {
			job_assumes(jr, mspolicy_copy(jr, jp));
		}

		if (shutdown_state && jm->hopefully_first_cnt == 0) {
			job_log(jr, LOG_APPLEONLY, "This process showed up to the party while all the guests were leaving. Odds are that it will have a miserable time.");
		}

		job_log(jr, LOG_DEBUG, "Created PID %u anonymously by PPID %u%s%s", anonpid, kp.kp_eproc.e_ppid, jp ? ": " : "", jp ? jp->label : "");
	}

	if (shutdown_state) {
		jm->shutting_down = true;
	}

	return jr;
}

job_t 
job_new(jobmgr_t jm, const char *label, const char *prog, const char *const *argv)
{
	const char *const *argv_tmp = argv;
	char auto_label[1000];
	const char *bn = NULL;
	char *co;
	size_t minlabel_len;
	int i, cc = 0;
	job_t j;

	launchd_assert(offsetof(struct job_s, kqjob_callback) == 0);

	if (jm->shutting_down) {
		errno = EINVAL;
		return NULL;
	}

	if (prog == NULL && argv == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (label == AUTO_PICK_LEGACY_LABEL) {
		bn = prog ? prog : basename((char *)argv[0]); /* prog for auto labels is kp.kp_kproc.p_comm */
		snprintf(auto_label, sizeof(auto_label), "%s.%s", sizeof(void *) == 8 ? "0xdeadbeeffeedface" : "0xbabecafe", bn);
		label = auto_label;
		/* This is so we can do gross things later. See NOTE_EXEC for anonymous jobs */
		minlabel_len = strlen(label) + MAXCOMLEN;
	} else {
		minlabel_len = strlen(label);
	}

	j = calloc(1, sizeof(struct job_s) + minlabel_len + 1);

	if (!jobmgr_assumes(jm, j != NULL)) {
		return NULL;
	}

	if (label == auto_label) {
		snprintf((char *)j->label, strlen(label) + 1, "%p.%s", j, bn);
	} else {
		strcpy((char *)j->label, label);
	}
	j->kqjob_callback = job_callback;
	j->mgr = jm;
	j->min_run_time = LAUNCHD_MIN_JOB_RUN_TIME;
	j->timeout = LAUNCHD_ADVISABLE_IDLE_TIMEOUT;
	j->exit_timeout = LAUNCHD_DEFAULT_EXIT_TIMEOUT;
	j->currently_ignored = true;
	j->ondemand = true;
	j->checkedin = true;

	if (prog) {
		j->prog = strdup(prog);
		if (!job_assumes(j, j->prog != NULL)) {
			goto out_bad;
		}
	}

	if (argv) {
		while (*argv_tmp++)
			j->argc++;

		for (i = 0; i < j->argc; i++) {
			cc += strlen(argv[i]) + 1;
		}

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

	LIST_INSERT_HEAD(&jm->jobs, j, sle);
	LIST_INSERT_HEAD(&label_hash[hash_label(j->label)], j, label_hash_sle);

	job_log(j, LOG_DEBUG, "Conceived");

	return j;

out_bad:
	if (j->prog) {
		free(j->prog);
	}
	free(j);

	return NULL;
}

job_t 
job_import(launch_data_t pload)
{
	job_t j = jobmgr_import2(root_jobmgr, pload);

	if (j == NULL) {
		return NULL;
	}

	return job_dispatch(j, false);
}

launch_data_t
job_import_bulk(launch_data_t pload)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_ARRAY);
	job_t *ja;
	size_t i, c = launch_data_array_get_count(pload);

	ja = alloca(c * sizeof(job_t ));

	for (i = 0; i < c; i++) {
		if ((ja[i] = jobmgr_import2(root_jobmgr, launch_data_array_get_index(pload, i)))) {
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
	bool found_key = false;

	switch (key[0]) {
	case 'k':
	case 'K':
		if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE) == 0) {
			j->ondemand = !value;
			found_key = true;
		}
		break;
	case 'o':
	case 'O':
		if (strcasecmp(key, LAUNCH_JOBKEY_ONDEMAND) == 0) {
			j->ondemand = value;
			found_key = true;
		}
		break;
	case 'd':
	case 'D':
		if (strcasecmp(key, LAUNCH_JOBKEY_DEBUG) == 0) {
			j->debug = value;
			found_key = true;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_DISABLED) == 0) {
			job_assumes(j, !value);
			found_key = true;
		}
		break;
	case 'h':
	case 'H':
		if (strcasecmp(key, LAUNCH_JOBKEY_HOPEFULLYEXITSLAST) == 0) {
			j->hopefully_exits_last = value;
			found_key = true;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_HOPEFULLYEXITSFIRST) == 0) {
			j->hopefully_exits_first = value;
			found_key = true;
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_SESSIONCREATE) == 0) {
			j->session_create = value;
			found_key = true;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_STARTONMOUNT) == 0) {
			j->start_on_mount = value;
			found_key = true;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_SERVICEIPC) == 0) {
			/* this only does something on Mac OS X 10.4 "Tiger" */
			found_key = true;
		}
		break;
	case 'l':
	case 'L':
		if (strcasecmp(key, LAUNCH_JOBKEY_LOWPRIORITYIO) == 0) {
			j->low_pri_io = value;
			found_key = true;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LAUNCHONLYONCE) == 0) {
			j->only_once = value;
			found_key = true;
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
			found_key = true;
		}
		break;
	case 'r':
	case 'R':
		if (strcasecmp(key, LAUNCH_JOBKEY_RUNATLOAD) == 0) {
			if (value) {
				/* We don't want value == false to change j->start_pending */
				j->start_pending = true;
			}
			found_key = true;
		}
		break;
	case 'e':
	case 'E':
		if (strcasecmp(key, LAUNCH_JOBKEY_ENABLEGLOBBING) == 0) {
			j->globargv = value;
			found_key = true;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_ENTERKERNELDEBUGGERBEFOREKILL) == 0) {
			j->debug_before_kill = value;
			found_key = true;
		}
		break;
	case 'w':
	case 'W':
		if (strcasecmp(key, LAUNCH_JOBKEY_WAITFORDEBUGGER) == 0) {
			j->wait4debugger = value;
			found_key = true;
		}
		break;
	default:
		break;
	}

	if (!found_key) {
		job_log(j, LOG_WARNING, "Unknown key for boolean: %s", key);
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
			job_reparent_hack(j, value);
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
		} else if (strcasecmp(key, LAUNCH_JOBKEY_SANDBOXPROFILE) == 0) {
			where2put = &j->seatbelt_profile;
		}
		break;
	default:
		job_log(j, LOG_WARNING, "Unknown key for string: %s", key);
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
	case 'e':
	case 'E':
		if (strcasecmp(key, LAUNCH_JOBKEY_EXITTIMEOUT) == 0) {
			if (value < 0) {
				job_log(j, LOG_WARNING, "Exit timeout less zero. Ignoring.");
			} else {
				j->exit_timeout = value;
			}
		}
		break;
	case 'n':
	case 'N':
		if (strcasecmp(key, LAUNCH_JOBKEY_NICE) == 0) {
			j->nice = value;
			j->setnice = true;
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
		} else if (strcasecmp(key, LAUNCH_JOBKEY_SANDBOXFLAGS) == 0) {
			j->seatbelt_flags = value;
		}

		break;
	default:
		job_log(j, LOG_WARNING, "Unknown key for integer: %s", key);
		break;
	}
}

void
job_import_opaque(job_t j, const char *key, launch_data_t value)
{
	switch (key[0]) {
	case 'q':
	case 'Q':
		if (strcasecmp(key, LAUNCH_JOBKEY_QUARANTINEDATA) == 0) {
			size_t tmpsz = launch_data_get_opaque_size(value);

			if (job_assumes(j, j->quarantine_data = malloc(tmpsz))) {
				memcpy(j->quarantine_data, launch_data_get_opaque(value), tmpsz);
				j->quarantine_data_sz = tmpsz;
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
		} else if (strcasecmp(key, LAUNCH_JOBKEY_SANDBOXFLAGS) == 0) {
			launch_data_dict_iterate(value, seatbelt_setup_flags, j);
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
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACHSERVICELOOKUPPOLICIES) == 0) {
			launch_data_dict_iterate(value, mspolicy_setup, j);
		}
		break;
	default:
		job_log(j, LOG_WARNING, "Unknown key for dictionary: %s", key);
		break;
	}
}

void
job_import_array(job_t j, const char *key, launch_data_t value)
{
	size_t i, value_cnt = launch_data_array_get_count(value);
	const char *str;

	switch (key[0]) {
	case 'p':
	case 'P':
		if (strcasecmp(key, LAUNCH_JOBKEY_PROGRAMARGUMENTS) == 0) {
			return;
		}
		break;
	case 'l':
	case 'L':
		if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADTOHOSTS) == 0) {
			return;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADFROMHOSTS) == 0) {
			return;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE) == 0) {
			job_log(j, LOG_NOTICE, "launchctl should have transformed the \"%s\" array to a string", LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE);
			return;
		}
		break;
	case 'q':
	case 'Q':
		if (strcasecmp(key, LAUNCH_JOBKEY_QUEUEDIRECTORIES) == 0) {
			for (i = 0; i < value_cnt; i++) {
				str = launch_data_get_string(launch_data_array_get_index(value, i));
				if (job_assumes(j, str != NULL)) {
					semaphoreitem_new(j, DIR_NOT_EMPTY, str);
				}
			}

		}
		break;
	case 'w':
	case 'W':
		if (strcasecmp(key, LAUNCH_JOBKEY_WATCHPATHS) == 0) {
			for (i = 0; i < value_cnt; i++) {
				str = launch_data_get_string(launch_data_array_get_index(value, i));
				if (job_assumes(j, str != NULL)) {
					semaphoreitem_new(j, PATH_CHANGES, str);
				}
			}
		}
		break;
	case 'b':
	case 'B':
		if (strcasecmp(key, LAUNCH_JOBKEY_BONJOURFDS) == 0) {
			socketgroup_setup(value, LAUNCH_JOBKEY_BONJOURFDS, j);
		} else if (strcasecmp(key, LAUNCH_JOBKEY_BINARYORDERPREFERENCE) == 0) {
			if (job_assumes(j, j->j_binpref = malloc(value_cnt * sizeof(*j->j_binpref)))) {
				j->j_binpref_cnt = value_cnt;
				for (i = 0; i < value_cnt; i++) {
					j->j_binpref[i] = launch_data_get_integer(launch_data_array_get_index(value, i));
				}
			}
		}
		break;
	case 's':
	case 'S':
		if (strcasecmp(key, LAUNCH_JOBKEY_STARTCALENDARINTERVAL) == 0) {
			for (i = 0; i < value_cnt; i++) {
				calendarinterval_new_from_obj(j, launch_data_array_get_index(value, i));
			}
		}
		break;
	default:
		job_log(j, LOG_WARNING, "Unknown key for array: %s", key);
		break;
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
	case LAUNCH_DATA_OPAQUE:
		job_import_opaque(j, key, obj);
		break;
	default:
		job_log(j, LOG_WARNING, "Unknown value type '%d' for key: %s", kind, key);
		break;
	}
}

job_t 
jobmgr_import2(jobmgr_t jm, launch_data_t pload)
{
	launch_data_t tmp, ldpa;
	const char *label = NULL, *prog = NULL;
	const char **argv = NULL;
	job_t j;

	if (pload == NULL) {
		return NULL;
	}

	if (launch_data_get_type(pload) != LAUNCH_DATA_DICTIONARY) {
		errno = EINVAL;
		return NULL;
	}

	if ((tmp = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_LABEL)) &&
			(launch_data_get_type(tmp) == LAUNCH_DATA_STRING)) {
		if (!(label = launch_data_get_string(tmp))) {
			errno = EINVAL;
			return NULL;
		}
	}

	if ((tmp = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAM)) &&
			(launch_data_get_type(tmp) == LAUNCH_DATA_STRING)) {
		prog = launch_data_get_string(tmp);
	}

	if ((ldpa = launch_data_dict_lookup(pload, LAUNCH_JOBKEY_PROGRAMARGUMENTS))) {
		size_t i, c;

		if (launch_data_get_type(ldpa) != LAUNCH_DATA_ARRAY) {
			errno = EINVAL;
			return NULL;
		}

		c = launch_data_array_get_count(ldpa);

		argv = alloca((c + 1) * sizeof(char *));

		for (i = 0; i < c; i++) {
			tmp = launch_data_array_get_index(ldpa, i);

			if (launch_data_get_type(tmp) != LAUNCH_DATA_STRING) {
				errno = EINVAL;
				return NULL;
			}

			argv[i] = launch_data_get_string(tmp);
		}

		argv[i] = NULL;
	}

	if ((j = job_find(label)) != NULL) {
		errno = EEXIST;
		return NULL;
	} else if (label[0] == '\0' || (strncasecmp(label, "", strlen("com.apple.launchd")) == 0) ||
			(strtol(label, NULL, 10) != 0)) {
		jobmgr_log(jm, LOG_ERR, "Somebody attempted to use a reserved prefix for a label: %s", label);
		/* the empty string, com.apple.launchd and number prefixes for labels are reserved */
		errno = EINVAL;
		return NULL;
	}

	if ((j = job_new(jm, label, prog, argv))) {
		launch_data_dict_iterate(pload, job_import_keys, j);
	}

	return j;
}

job_t 
job_find(const char *label)
{
	job_t ji;

	LIST_FOREACH(ji, &label_hash[hash_label(label)], label_hash_sle) {
		if (strcmp(ji->label, label) == 0) {
			return ji;
		}
	}

	errno = ESRCH;
	return NULL;
}

job_t
jobmgr_find_by_pid(jobmgr_t jm, pid_t p, bool create_anon)
{
	job_t ji = NULL;

	LIST_FOREACH(ji, &jm->active_jobs[ACTIVE_JOB_HASH(p)], pid_hash_sle) {
		if (ji->p == p) {
			break;
		}
	}

	if (ji) {
		return ji;
	} else if (create_anon) {
		return job_new_anonymous(jm, p);
	} else {
		return NULL;
	}
}

job_t 
job_mig_intran2(jobmgr_t jm, mach_port_t mport, pid_t upid)
{
	jobmgr_t jmi;
	job_t ji;

	if (jm->jm_port == mport) {
		jobmgr_assumes(jm, (ji = jobmgr_find_by_pid(jm, upid, true)) != NULL);
		return ji;
	}

	SLIST_FOREACH(jmi, &jm->submgrs, sle) {
		job_t jr;

		if ((jr = job_mig_intran2(jmi, mport, upid))) {
			return jr;
		}
	}

	LIST_FOREACH(ji, &jm->jobs, sle) {
		if (ji->j_port == mport) {
			return ji;
		}
	}

	return NULL;
}

job_t 
job_mig_intran(mach_port_t p)
{
	struct ldcred ldc;
	job_t jr;

	runtime_get_caller_creds(&ldc);

	jr = job_mig_intran2(root_jobmgr, p, ldc.pid);

	if (!jobmgr_assumes(root_jobmgr, jr != NULL)) {
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
		struct kinfo_proc kp;
		size_t len = sizeof(kp);

		mib[3] = ldc.pid;

		if (jobmgr_assumes(root_jobmgr, sysctl(mib, 4, &kp, &len, NULL, 0) != -1)) {
			jobmgr_log(root_jobmgr, LOG_ERR, "%s() was confused by PID %u UID %u EUID %u Mach Port 0x%x: %s", __func__, ldc.pid, ldc.uid, ldc.euid, p, kp.kp_proc.p_comm);
		}
	}

	return jr;
}

job_t
job_find_by_service_port(mach_port_t p)
{
	struct machservice *ms;

	LIST_FOREACH(ms, &port_hash[HASH_PORT(p)], port_hash_sle) {
		if (ms->port == p) {
			return ms->job;
		}
	}

	return NULL;
}

void
job_mig_destructor(job_t j)
{
	if (j->unload_at_mig_return) {
		job_log(j, LOG_NOTICE, "Unloading PID %u at MIG return.", j->p);
		job_remove(j);
	}

	calendarinterval_sanity_check();
}

void
job_export_all2(jobmgr_t jm, launch_data_t where)
{
	jobmgr_t jmi;
	job_t ji;

	SLIST_FOREACH(jmi, &jm->submgrs, sle) {
		job_export_all2(jmi, where);
	}

	LIST_FOREACH(ji, &jm->jobs, sle) {
		launch_data_t tmp;

		if (jobmgr_assumes(jm, (tmp = job_export(ji)) != NULL)) {
			launch_data_dict_insert(where, tmp, ji->label);
		}
	}
}

launch_data_t
job_export_all(void)
{
	launch_data_t resp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (launchd_assumes(resp != NULL)) {
		job_export_all2(root_jobmgr, resp);
	}

	return resp;
}

void
job_reap(job_t j)
{
	struct timeval tve, tvd;
	struct rusage ru;
	int status;

	job_log(j, LOG_DEBUG, "Reaping");

	if (j->weird_bootstrap) {
		mach_msg_size_t mxmsgsz = sizeof(union __RequestUnion__job_mig_protocol_vproc_subsystem);

		if (job_mig_protocol_vproc_subsystem.maxsize > mxmsgsz) {
			mxmsgsz = job_mig_protocol_vproc_subsystem.maxsize;
		}

		job_assumes(j, runtime_add_mport(j->mgr->jm_port, protocol_vproc_server, mxmsgsz) == KERN_SUCCESS);
		j->weird_bootstrap = false;
	}

	if (j->log_redirect_fd && (!j->wait4pipe_eof || j->mgr->shutting_down)) {
		job_assumes(j, runtime_close(j->log_redirect_fd) != -1);
		j->log_redirect_fd = 0;
	}

	if (j->forkfd) {
		job_assumes(j, runtime_close(j->forkfd) != -1);
		j->forkfd = 0;
	}

	if (j->anonymous) {
		status = 0;
		memset(&ru, 0, sizeof(ru));
	} else if (!job_assumes(j, wait4(j->p, &status, 0, &ru) != -1)) {
		job_log(j, LOG_NOTICE, "Working around 5020256. Assuming the job crashed.");

		status = W_EXITCODE(0, SIGSEGV);

		memset(&ru, 0, sizeof(ru));
	}

	if (j->exit_timeout) {
		kevent_mod((uintptr_t)&j->exit_timeout, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	}

	total_children--;
	LIST_REMOVE(j, pid_hash_sle);

	job_assumes(j, gettimeofday(&tve, NULL) != -1);

	if (j->wait_reply_port) {
		job_log(j, LOG_DEBUG, "MPM wait reply being sent");
		job_assumes(j, job_mig_wait_reply(j->wait_reply_port, 0, status) == 0);
		j->wait_reply_port = MACH_PORT_NULL;
	}

	if (j->sent_sigterm_time.tv_sec) {
		timersub(&tve, &j->sent_sigterm_time,  &tvd);

		job_log(j, LOG_INFO, "Exited %ld.%06d seconds after %s was sent",
				tvd.tv_sec, tvd.tv_usec, signal_to_C_name(j->sent_sigkill ? SIGKILL : SIGTERM));
	}

#if DO_RUSAGE_SUMMATION
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
#endif

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

	if (j->hopefully_exits_first) {
		j->mgr->hopefully_first_cnt--;
	} else if (!j->anonymous && !j->hopefully_exits_last) {
		j->mgr->normal_active_cnt--;
	}
	j->last_exit_status = status;
	j->sent_sigkill = false;
	j->p = 0;
}

void
jobmgr_dispatch_all(jobmgr_t jm, bool newmounthack)
{
	jobmgr_t jmi, jmn;
	job_t ji, jn;

	if (jm->shutting_down) {
		return;
	}

	SLIST_FOREACH_SAFE(jmi, &jm->submgrs, sle, jmn) {
		jobmgr_dispatch_all(jmi, newmounthack);
	}

	LIST_FOREACH_SAFE(ji, &jm->jobs, sle, jn) {
		if (newmounthack && ji->start_on_mount) {
			ji->start_pending = true;
		}

		job_dispatch(ji, false);
	}
}

job_t
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
	if (!job_active(j)) {
		if (job_useless(j)) {
			job_remove(j);
			return NULL;
		} else if (kickstart || job_keepalive(j)) {
			job_start(j);
		} else {
			job_watch(j);
		}
	} else {
		job_log(j, LOG_DEBUG, "Tried to dispatch an already active job.");
	}

	return j;
}

void
job_log_stdouterr(job_t j)
{
	char *msg, *bufindex, *buf = malloc(BIG_PIPE_SIZE + 1);
	ssize_t rsz;

	if (!job_assumes(j, buf != NULL)) {
		return;
	}

	bufindex = buf;

	rsz = read(j->log_redirect_fd, buf, BIG_PIPE_SIZE);

	if (rsz == 0) {
		job_log(j, LOG_DEBUG, "Standard out/error pipe closed");
		job_assumes(j, runtime_close(j->log_redirect_fd) != -1);
		j->log_redirect_fd = 0;
		job_dispatch(j, false);
	} else if (job_assumes(j, rsz != -1)) {
		buf[rsz] = '\0';

		while ((msg = strsep(&bufindex, "\n\r"))) {
			if (msg[0]) {
				job_log(j, LOG_NOTICE, "Standard out/error: %s", msg);
			}
		}
	}

	free(buf);
}

void
job_kill(job_t j)
{
	if (!j->p || j->anonymous) {
		return;
	}

	job_assumes(j, kill(j->p, SIGKILL) != -1);

	j->sent_sigkill = true;

	job_assumes(j, kevent_mod((uintptr_t)&j->exit_timeout, EVFILT_TIMER,
				EV_ADD, NOTE_SECONDS, LAUNCHD_SIGKILL_TIMER, j) != -1);
}

void
job_callback_proc(job_t j, int flags, int fflags)
{
	if ((fflags & NOTE_EXEC) && j->anonymous) {
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, j->p };
		struct kinfo_proc kp;
		size_t len = sizeof(kp);

		if (job_assumes(j, sysctl(mib, 4, &kp, &len, NULL, 0) != -1)) {
			char newlabel[1000];

			snprintf(newlabel, sizeof(newlabel), "%p.%s", j, kp.kp_proc.p_comm);

			job_log(j, LOG_DEBUG, "Program changed. Updating the label to: %s", newlabel);

			LIST_REMOVE(j, label_hash_sle);
			strcpy((char *)j->label, newlabel);
			LIST_INSERT_HEAD(&label_hash[hash_label(j->label)], j, label_hash_sle);
		}
	}

	if (fflags & NOTE_FORK) {
		job_log(j, LOG_DEBUG, "Called fork()");
	}

	if (fflags & NOTE_EXIT) {
		job_reap(j);

		if (j->anonymous) {
			job_remove(j);
			j = NULL;
		} else {
			j = job_dispatch(j, false);
		}
	}

	if (j && (fflags & NOTE_REAP)) {
		job_assumes(j, flags & EV_ONESHOT);
		job_assumes(j, flags & EV_EOF);

		job_assumes(j, j->p == 0);
	}
}

void
job_callback_timer(job_t j, void *ident)
{
	if (j == ident) {
		job_dispatch(j, true);
	} else if (&j->start_interval == ident) {
		j->start_pending = true;
		job_dispatch(j, false);
	} else if (&j->exit_timeout == ident) {
		if (j->sent_sigkill) {
			struct timeval tvd, tve;

			job_assumes(j, gettimeofday(&tve, NULL) != -1);
			timersub(&tve, &j->sent_sigterm_time,  &tvd);
			tvd.tv_sec -= j->exit_timeout;
			job_log(j, LOG_ERR, "Did not die after sending SIGKILL %lu seconds ago...", tvd.tv_sec);
		} else {
			job_force_sampletool(j);
			if (j->debug_before_kill) {
				job_log(j, LOG_NOTICE, "Exit timeout elapsed. Entering the kernel debugger.");
				job_assumes(j, host_reboot(mach_host_self(), HOST_REBOOT_DEBUGGER) == KERN_SUCCESS);
			}
			job_log(j, LOG_WARNING, "Exit timeout elapsed (%u seconds). Killing.", j->exit_timeout);
			job_kill(j);
		}
	} else {
		job_assumes(j, false);
	}
}

void
job_callback_read(job_t j, int ident)
{
	if (ident == j->log_redirect_fd) {
		job_log_stdouterr(j);
	} else {
		socketgroup_callback(j);
	}
}

void
jobmgr_reap_bulk(jobmgr_t jm, struct kevent *kev)
{
	jobmgr_t jmi;
	job_t j;

	SLIST_FOREACH(jmi, &jm->submgrs, sle) {
		jobmgr_reap_bulk(jmi, kev);
	}

	if ((j = jobmgr_find_by_pid(jm, kev->ident, false))) {
		kev->udata = j;
		job_callback(j, kev);
	}
}

void
jobmgr_callback(void *obj, struct kevent *kev)
{
	jobmgr_t jm = obj;

	switch (kev->filter) {
	case EVFILT_PROC:
		jobmgr_reap_bulk(jm, kev);
		if (launchd_assumes(root_jobmgr != NULL)) {
			root_jobmgr = jobmgr_do_garbage_collection(root_jobmgr);
		}
		break;
	case EVFILT_SIGNAL:
		switch (kev->ident) {
		case SIGTERM:
			return launchd_shutdown();
		case SIGUSR1:
			return calendarinterval_callback();
		default:
			return (void)jobmgr_assumes(jm, false);
		}
		break;
	case EVFILT_FS:
		if (kev->fflags & VQ_MOUNT) {
			jobmgr_dispatch_all(jm, true);
		}
		jobmgr_dispatch_all_semaphores(jm);
		break;
	case EVFILT_TIMER:
		if (kev->ident == (uintptr_t)&sorted_calendar_events) {
			calendarinterval_callback();
		} else {
			jobmgr_log(jm, LOG_NOTICE, "Still alive with %u children.", total_children);
		}
		break;
	default:
		return (void)jobmgr_assumes(jm, false);
	}
}

void
job_callback(void *obj, struct kevent *kev)
{
	job_t j = obj;

	job_log(j, LOG_DEBUG, "Dispatching kevent callback.");

	switch (kev->filter) {
	case EVFILT_PROC:
		return job_callback_proc(j, kev->flags, kev->fflags);
	case EVFILT_TIMER:
		return job_callback_timer(j, (void *)kev->ident);
	case EVFILT_VNODE:
		return semaphoreitem_callback(j, kev);
	case EVFILT_READ:
		return job_callback_read(j, kev->ident);
	case EVFILT_MACHPORT:
		return (void)job_dispatch(j, true);
	default:
		return (void)job_assumes(j, false);
	}
}

void
job_start(job_t j)
{
	int spair[2];
	int execspair[2];
	int oepair[2];
	char nbuf[64];
	pid_t c;
	bool sipc = false;
	time_t td;
	u_int proc_fflags = /* NOTE_EXEC|NOTE_FORK| */ NOTE_EXIT|NOTE_REAP;

	if (!job_assumes(j, j->mgr != NULL)) {
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

	j->sent_sigterm_time.tv_sec = 0;
	j->sent_sigterm_time.tv_usec = 0;

	if (!j->legacy_mach_job) {
		sipc = (!SLIST_EMPTY(&j->sockets) || !SLIST_EMPTY(&j->machservices));
	}

	j->checkedin = false;

	if (sipc) {
		job_assumes(j, socketpair(AF_UNIX, SOCK_STREAM, 0, spair) != -1);
	}

	job_assumes(j, socketpair(AF_UNIX, SOCK_STREAM, 0, execspair) != -1);

	if (!j->legacy_mach_job && job_assumes(j, pipe(oepair) != -1)) {
		j->log_redirect_fd = _fd(oepair[0]);
		job_assumes(j, fcntl(j->log_redirect_fd, F_SETFL, O_NONBLOCK) != -1);
		job_assumes(j, kevent_mod(j->log_redirect_fd, EVFILT_READ, EV_ADD, 0, 0, j) != -1);
	}

	time(&j->start_time);

	switch (c = runtime_fork(j->weird_bootstrap ? j->j_port : j->mgr->jm_port)) {
	case -1:
		job_log_error(j, LOG_ERR, "fork() failed, will try again in one second");
		job_assumes(j, runtime_close(execspair[0]) == 0);
		job_assumes(j, runtime_close(execspair[1]) == 0);
		if (sipc) {
			job_assumes(j, runtime_close(spair[0]) == 0);
			job_assumes(j, runtime_close(spair[1]) == 0);
		}
		break;
	case 0:
		if (_vproc_post_fork_ping()) {
			_exit(EXIT_FAILURE);
		}
		if (!j->legacy_mach_job) {
			job_assumes(j, dup2(oepair[1], STDOUT_FILENO) != -1);
			job_assumes(j, dup2(oepair[1], STDERR_FILENO) != -1);
			job_assumes(j, runtime_close(oepair[1]) != -1);
		}
		job_assumes(j, runtime_close(execspair[0]) == 0);
		/* wait for our parent to say they've attached a kevent to us */
		read(_fd(execspair[1]), &c, sizeof(c));

		if (sipc) {
			job_assumes(j, runtime_close(spair[0]) == 0);
			snprintf(nbuf, sizeof(nbuf), "%d", spair[1]);
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
		}
		job_start_child(j);
		break;
	default:
		job_log(j, LOG_DEBUG, "Started as PID: %u", c);

		j->start_pending = false;

		total_children++;
		LIST_INSERT_HEAD(&j->mgr->active_jobs[ACTIVE_JOB_HASH(c)], j, pid_hash_sle);

		if (j->per_user && !did_first_per_user_launchd_BootCache_hack) {
			did_first_per_user_launchd_BootCache_hack = true;
		}

		if (!j->legacy_mach_job) {
			job_assumes(j, runtime_close(oepair[1]) != -1);
		}
		j->p = c;
		if (j->hopefully_exits_first) {
			j->mgr->hopefully_first_cnt++;
		} else if (!j->hopefully_exits_last) {
			j->mgr->normal_active_cnt++;
		}
		j->forkfd = _fd(execspair[0]);
		job_assumes(j, runtime_close(execspair[1]) == 0);
		if (sipc) {
			job_assumes(j, runtime_close(spair[1]) == 0);
			ipc_open(_fd(spair[0]), j);
		}
		if (job_assumes(j, kevent_mod(c, EVFILT_PROC, EV_ADD, proc_fflags, 0, root_jobmgr ? root_jobmgr : j->mgr) != -1)) {
			job_ignore(j);
		} else {
			job_reap(j);
		}

		if (!j->stall_before_exec) {
			job_uncork_fork(j);
		}
		break;
	}
}

static void
do_first_per_user_launchd_hack(void)
{
	char *bcct_tool[] = { "/usr/sbin/BootCacheControl", "tag", NULL };
	int dummystatus;
	pid_t bcp;

	if (launchd_assumes((bcp = vfork()) != -1)) {
		if (bcp == 0) {
			execve(bcct_tool[0], bcct_tool, environ);
			_exit(EXIT_FAILURE);
		} else {
			launchd_assumes(waitpid(bcp, &dummystatus, 0) != -1);
		}
	}
}

void
job_start_child(job_t j)
{
	const char *file2exec = "/usr/libexec/launchproxy";
	const char **argv;
	posix_spawnattr_t spattr;
	int gflags = GLOB_NOSORT|GLOB_NOCHECK|GLOB_TILDE|GLOB_DOOFFS;
	pid_t junk_pid;
	glob_t g;
	short spflags = POSIX_SPAWN_SETEXEC;
	size_t binpref_out_cnt = 0;
	int i;

	if (j->per_user && !did_first_per_user_launchd_BootCache_hack) {
		do_first_per_user_launchd_hack();
	}

	job_assumes(j, posix_spawnattr_init(&spattr) == 0);

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
		for (i = 0; i < j->argc; i++) {
			argv[i + 1] = j->argv[i];
		}
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

	if (j->wait4debugger) {
		job_log(j, LOG_WARNING, "Spawned and waiting for the debugger to attach before continuing...");
		spflags |= POSIX_SPAWN_START_SUSPENDED;
	}

	job_assumes(j, posix_spawnattr_setflags(&spattr, spflags) == 0);

	if (j->j_binpref_cnt) {
		job_assumes(j, posix_spawnattr_setbinpref_np(&spattr, j->j_binpref_cnt, j->j_binpref, &binpref_out_cnt) == 0);
		job_assumes(j, binpref_out_cnt == j->j_binpref_cnt);
	}

	for (i = 1; i < NSIG; i++) {
		signal(i, SIG_DFL);
	}

	if (j->quarantine_data) {
		qtn_proc_t qp;

		if (job_assumes(j, qp = qtn_proc_alloc())) {
			if (job_assumes(j, qtn_proc_init_with_data(qp, j->quarantine_data, j->quarantine_data_sz) == 0)) {
				job_assumes(j, qtn_proc_apply_to_self(qp) == 0);
			}
		}
	}

	if (j->seatbelt_profile) {
		char *seatbelt_err_buf = NULL;

		if (!job_assumes(j, sandbox_init(j->seatbelt_profile, j->seatbelt_flags, &seatbelt_err_buf) != -1)) {
			if (seatbelt_err_buf) {
				job_log(j, LOG_ERR, "Sandbox failed to init: %s", seatbelt_err_buf);
			}
			goto out_bad;
		}
	}

	if (j->prog) {
		errno = posix_spawn(&junk_pid, j->inetcompat ? file2exec : j->prog, NULL, &spattr, (char *const*)argv, environ);
		job_log_error(j, LOG_ERR, "posix_spawn(\"%s\", ...)", j->prog);
	} else {
		errno = posix_spawnp(&junk_pid, j->inetcompat ? file2exec : argv[0], NULL, &spattr, (char *const*)argv, environ);
		job_log_error(j, LOG_ERR, "posix_spawnp(\"%s\", ...)", argv[0]);
	}

out_bad:
	_exit(EXIT_FAILURE);
}

void
jobmgr_export_env_from_other_jobs(jobmgr_t jm, launch_data_t dict)
{
	launch_data_t tmp;
	struct envitem *ei;
	job_t ji;

	if (jm->parentmgr) {
		jobmgr_export_env_from_other_jobs(jm->parentmgr, dict);
	} else {
		char **tmpenviron = environ;
		for (; *tmpenviron; tmpenviron++) {
			char envkey[1024];
			launch_data_t s = launch_data_alloc(LAUNCH_DATA_STRING);
			launch_data_set_string(s, strchr(*tmpenviron, '=') + 1);
			strncpy(envkey, *tmpenviron, sizeof(envkey));
			*(strchr(envkey, '=')) = '\0';
			launch_data_dict_insert(dict, s, envkey);
		}
	}

	LIST_FOREACH(ji, &jm->jobs, sle) {
		SLIST_FOREACH(ei, &ji->global_env, sle) {
			if ((tmp = launch_data_new_string(ei->value))) {
				launch_data_dict_insert(dict, tmp, ei->key);
			}
		}
	}
}

void
jobmgr_setup_env_from_other_jobs(jobmgr_t jm)
{
	struct envitem *ei;
	job_t ji;

	if (jm->parentmgr) {
		jobmgr_setup_env_from_other_jobs(jm->parentmgr);
	}

	LIST_FOREACH(ji, &jm->jobs, sle) {
		SLIST_FOREACH(ei, &ji->global_env, sle) {
			setenv(ei->key, ei->value, 1);
		}
	}
}

void
job_find_and_blame_pids_with_weird_uids(job_t j)
{
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
	size_t i, kp_cnt, len = 10*1024*1024;
	struct kinfo_proc *kp = malloc(len);
	uid_t u = j->mach_uid;

	if (!job_assumes(j, kp != NULL)) {
		return;
	}
	if (!job_assumes(j, sysctl(mib, 3, kp, &len, NULL, 0) != -1)) {
		goto out;
	}

	kp_cnt = len / sizeof(struct kinfo_proc);

	for (i = 0; i < kp_cnt; i++) {
		uid_t i_euid = kp[i].kp_eproc.e_ucred.cr_uid;
		uid_t i_uid = kp[i].kp_eproc.e_pcred.p_ruid;
		uid_t i_svuid = kp[i].kp_eproc.e_pcred.p_svuid;
		pid_t i_pid = kp[i].kp_proc.p_pid;

		if (i_euid != u && i_uid != u && i_svuid != u) {
			continue;
		}

		job_log(j, LOG_ERR, "PID %u \"%s\" has no account to back it! Real/effective/saved UIDs: %u/%u/%u",
				i_pid, kp[i].kp_proc.p_comm, i_uid, i_euid, i_svuid);

		/* Ask the accountless process to exit. */
		job_assumes(j, kill(i_pid, SIGTERM) != -1);
	}

out:
	free(kp);
}

void
job_postfork_become_user(job_t j)
{
	char loginname[2000];
	char tmpdirpath[PATH_MAX];
	char shellpath[PATH_MAX];
	char homedir[PATH_MAX];
	struct passwd *pwe;
	size_t r;
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
			job_find_and_blame_pids_with_weird_uids(j);
			_exit(EXIT_FAILURE);
		}
	} else {
		return;
	}

	strlcpy(shellpath, pwe->pw_shell, sizeof(shellpath));
	strlcpy(loginname, pwe->pw_name, sizeof(loginname));
	strlcpy(homedir, pwe->pw_dir, sizeof(homedir));

	if (pwe->pw_expire && time(NULL) >= pwe->pw_expire) {
		job_log(j, LOG_ERR, "Expired account");
		_exit(EXIT_FAILURE);
	}

	desired_uid = pwe->pw_uid;
	desired_gid = pwe->pw_gid;

	if (j->username && strcmp(j->username, loginname) != 0) {
		job_log(j, LOG_WARNING, "Suspicious setup: User \"%s\" maps to user: %s", j->username, loginname);
	} else if (j->mach_uid && (j->mach_uid != desired_uid)) {
		job_log(j, LOG_WARNING, "Suspicious setup: UID %u maps to UID %u", j->mach_uid, desired_uid);
	}

	if (j->groupname) {
		struct group *gre;

		if ((gre = getgrnam(j->groupname)) == NULL) {
			job_log(j, LOG_ERR, "getgrnam(\"%s\") failed", j->groupname);
			_exit(EXIT_FAILURE);
		}

		desired_gid = gre->gr_gid;
	}

	if (!job_assumes(j, setlogin(loginname) != -1)) {
		_exit(EXIT_FAILURE);
	}

	if (!job_assumes(j, setgid(desired_gid) != -1)) {
		_exit(EXIT_FAILURE);
	}

	/*
	 * The kernel team and the DirectoryServices team want initgroups()
	 * called after setgid(). See 4616864 for more information.
	 */

	if (!j->no_init_groups) {
		if (!job_assumes(j, initgroups(loginname, desired_gid) != -1)) {
			_exit(EXIT_FAILURE);
		}
	}

	if (!job_assumes(j, setuid(desired_uid) != -1)) {
		_exit(EXIT_FAILURE);
	}

	r = confstr(_CS_DARWIN_USER_TEMP_DIR, tmpdirpath, sizeof(tmpdirpath));

	if (r > 0 && r < sizeof(tmpdirpath)) {
		setenv("TMPDIR", tmpdirpath, 0);
	}

	setenv("SHELL", shellpath, 0);
	setenv("HOME", homedir, 0);
	setenv("USER", loginname, 0);
	setenv("LOGNAME", loginname, 0);
}

void
job_setup_attributes(job_t j)
{
	struct limititem *li;
	struct envitem *ei;

	if (j->setnice) {
		job_assumes(j, setpriority(PRIO_PROCESS, 0, j->nice) != -1);
	}

	SLIST_FOREACH(li, &j->limits, sle) {
		struct rlimit rl;

		if (!job_assumes(j, getrlimit(li->which, &rl) != -1)) {
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
		job_assumes(j, setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE) != -1);
	}
	if (j->rootdir) {
		job_assumes(j, chroot(j->rootdir) != -1);
		job_assumes(j, chdir(".") != -1);
	}

	job_postfork_become_user(j);

	if (j->workingdir) {
		job_assumes(j, chdir(j->workingdir) != -1);
	}

	if (j->setmask) {
		umask(j->mask);
	}

	job_setup_fd(j, STDOUT_FILENO, j->stdoutpath, O_WRONLY|O_APPEND|O_CREAT);
	job_setup_fd(j, STDERR_FILENO, j->stderrpath, O_WRONLY|O_APPEND|O_CREAT);

	jobmgr_setup_env_from_other_jobs(j->mgr);

	SLIST_FOREACH(ei, &j->env, sle) {
		setenv(ei->key, ei->value, 1);
	}

	job_assumes(j, setsid() != -1);
}

void
job_setup_fd(job_t j, int target_fd, const char *path, int flags)
{
	int fd;

	if (!path) {
		return;
	}

	if ((fd = open(path, flags|O_NOCTTY, DEFFILEMODE)) == -1) {
		job_log_error(j, LOG_WARNING, "open(\"%s\", ...)", path);
		return;
	}

	job_assumes(j, dup2(fd, target_fd) != -1);
	job_assumes(j, runtime_close(fd) == 0);
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
	struct calendarinterval *ci_iter, *ci_prev = NULL;
	time_t later, head_later;

	later = cronemu(ci->when.tm_mon, ci->when.tm_mday, ci->when.tm_hour, ci->when.tm_min);

	if (ci->when.tm_wday != -1) {
		time_t otherlater = cronemu_wday(ci->when.tm_wday, ci->when.tm_hour, ci->when.tm_min);

		if (ci->when.tm_mday == -1) {
			later = otherlater;
		} else {
			later = later < otherlater ? later : otherlater;
		}
	}

	ci->when_next = later;

	LIST_FOREACH(ci_iter, &sorted_calendar_events, global_sle) {
		if (ci->when_next < ci_iter->when_next) {
			LIST_INSERT_BEFORE(ci_iter, ci, global_sle);
			break;
		}

		ci_prev = ci_iter;
	}

	if (ci_iter == NULL) {
		/* ci must want to fire after every other timer, or there are no timers */

		if (LIST_EMPTY(&sorted_calendar_events)) {
			LIST_INSERT_HEAD(&sorted_calendar_events, ci, global_sle);
		} else {
			LIST_INSERT_AFTER(ci_prev, ci, global_sle);
		}
	}

	head_later = LIST_FIRST(&sorted_calendar_events)->when_next;

	/* Workaround 5225889 */
	kevent_mod((uintptr_t)&sorted_calendar_events, EVFILT_TIMER, EV_DELETE, 0, 0, root_jobmgr);

	if (job_assumes(j, kevent_mod((uintptr_t)&sorted_calendar_events, EVFILT_TIMER, EV_ADD, NOTE_ABSOLUTE|NOTE_SECONDS, head_later, root_jobmgr) != -1)) {
		char time_string[100];
		size_t time_string_len;

		ctime_r(&later, time_string);
		time_string_len = strlen(time_string);

		if (time_string_len && time_string[time_string_len - 1] == '\n') {
			time_string[time_string_len - 1] = '\0';
		}

		job_log(j, LOG_INFO, "Scheduled to run again at %s", time_string);
	}
}

static void
extract_rcsid_substr(const char *i, char *o, size_t osz)
{
	char *rcs_rev_tmp = strchr(i, ' ');

	if (!rcs_rev_tmp) {
		strlcpy(o, i, osz);
	} else {
		strlcpy(o, rcs_rev_tmp + 1, osz);
		rcs_rev_tmp = strchr(o, ' ');
		if (rcs_rev_tmp) {
			*rcs_rev_tmp = '\0';
		}
	}
}

void
jobmgr_log_bug(jobmgr_t jm, const char *rcs_rev, const char *path, unsigned int line, const char *test)
{
	int saved_errno = errno;
	const char *file = strrchr(path, '/');
	char buf[100];

	extract_rcsid_substr(rcs_rev, buf, sizeof(buf));

	if (!file) {
		file = path;
	} else {
		file += 1;
	}

	jobmgr_log(jm, LOG_NOTICE, "Bug: %s:%u (%s):%u: %s", file, line, buf, saved_errno, test);
}

void
job_log_bug(job_t j, const char *rcs_rev, const char *path, unsigned int line, const char *test)
{
	int saved_errno = errno;
	const char *file = strrchr(path, '/');
	char buf[100];

	extract_rcsid_substr(rcs_rev, buf, sizeof(buf));

	if (!file) {
		file = path;
	} else {
		file += 1;
	}

	job_log(j, LOG_NOTICE, "Bug: %s:%u (%s):%u: %s", file, line, buf, saved_errno, test);
}

void
job_logv(job_t j, int pri, int err, const char *msg, va_list ap)
{
	char *newmsg;
	char *newlabel;
	int oldmask = 0;
	size_t i, o, jlabel_len = strlen(j->label), newmsgsz;

	/*
	 * Hack: If bootstrap_port is set, we must be on the child side of a
	 * fork(), but before the exec*(). Let's route the log message back to
	 * launchd proper.
	 */
	if (bootstrap_port) {
		return _vproc_logv(pri, err, msg, ap);
	}

	newlabel = alloca((jlabel_len + 1) * 2);
	newmsgsz = (jlabel_len + 1) * 2 + strlen(msg) + 100;
	newmsg = alloca(newmsgsz);

	for (i = 0, o = 0; i < jlabel_len; i++, o++) {
		if (j->label[i] == '%') {
			newlabel[o] = '%';
			o++;
		}
		newlabel[o] = j->label[i];
	}
	newlabel[o] = '\0';

	if (err) {
		snprintf(newmsg, newmsgsz, "%s: %s: %s", newlabel, msg, strerror(err));
	} else {
		snprintf(newmsg, newmsgsz, "%s: %s", newlabel, msg);
	}

	if (j->debug) {
		oldmask = setlogmask(LOG_UPTO(LOG_DEBUG));
	}

	jobmgr_logv(j->mgr, pri, 0, newmsg, ap);

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

#if 0
void
jobmgr_log_error(jobmgr_t jm, int pri, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	jobmgr_logv(jm, pri, errno, msg, ap);
	va_end(ap);
}
#endif

void
jobmgr_log(jobmgr_t jm, int pri, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	jobmgr_logv(jm, pri, 0, msg, ap);
	va_end(ap);
}

void
jobmgr_logv(jobmgr_t jm, int pri, int err, const char *msg, va_list ap)
{
	char *newmsg;
	char *newname;
	size_t i, o, jmname_len = strlen(jm->name), newmsgsz;

	newname = alloca((jmname_len + 1) * 2);
	newmsgsz = (jmname_len + 1) * 2 + strlen(msg) + 100;
	newmsg = alloca(newmsgsz);

	for (i = 0, o = 0; i < jmname_len; i++, o++) {
		if (jm->name[i] == '%') {
			newname[o] = '%';
			o++;
		}
		newname[o] = jm->name[i];
	}
	newname[o] = '\0';

	if (err) {
		snprintf(newmsg, newmsgsz, "%s: %s: %s", newname, msg, strerror(err));
	} else {
		snprintf(newmsg, newmsgsz, "%s: %s", newname, msg);
	}

	if (jm->parentmgr) {
		jobmgr_logv(jm->parentmgr, pri, 0, newmsg, ap);
	} else {
		runtime_vsyslog(pri, newmsg, ap);
	}
}

void    
semaphoreitem_ignore(job_t j, struct semaphoreitem *si)
{       
	if (si->fd != -1) {
		job_log(j, LOG_DEBUG, "Ignoring Vnode: %d", si->fd);
		job_assumes(j, kevent_mod(si->fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL) != -1);
	}
}

void
semaphoreitem_watch(job_t j, struct semaphoreitem *si)
{
	char parentdir_path[PATH_MAX], *which_path = si->what;
	int fflags = 0;
	
	switch (si->why) {
	case PATH_EXISTS:
		fflags = NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE|NOTE_EXTEND|NOTE_WRITE;
		strlcpy(parentdir_path, dirname(si->what), sizeof(parentdir_path));
		which_path = parentdir_path;
		break;
	case PATH_MISSING:
		fflags = NOTE_DELETE|NOTE_RENAME;
		break;
	case DIR_NOT_EMPTY:
	case PATH_CHANGES:
		fflags = NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE|NOTE_EXTEND|NOTE_WRITE|NOTE_ATTRIB|NOTE_LINK;
		break;
	default:
		return;
	}

	if (si->fd == -1) {
		si->fd = _fd(open(which_path, O_EVTONLY|O_NOCTTY));
	}

	if (si->fd == -1) {
		return job_log_error(j, LOG_ERR, "Watchpath monitoring failed on \"%s\"", which_path);
	}

	job_log(j, LOG_DEBUG, "Watching Vnode: %d", si->fd);
	job_assumes(j, kevent_mod(si->fd, EVFILT_VNODE, EV_ADD, fflags, 0, j) != -1);
}

void
semaphoreitem_callback(job_t j, struct kevent *kev)
{
	char invalidation_reason[100] = "";
	struct semaphoreitem *si;

	SLIST_FOREACH(si, &j->semaphores, sle) {
		switch (si->why) {
		case PATH_CHANGES:
		case PATH_EXISTS:
		case PATH_MISSING:
		case DIR_NOT_EMPTY:
			break;
		default:
			continue;
		}

		if (si->fd == (int)kev->ident) {
			break;
		}
	}

	if (!job_assumes(j, si != NULL)) {
		return;
	}

	if (NOTE_DELETE & kev->fflags) {
		strcat(invalidation_reason, "deleted");
	}

	if (NOTE_RENAME & kev->fflags) {
		if (invalidation_reason[0]) {
			strcat(invalidation_reason, "/renamed");
		} else {
			strcat(invalidation_reason, "renamed");
		}
	}

	if (NOTE_REVOKE & kev->fflags) {
		if (invalidation_reason[0]) {
			strcat(invalidation_reason, "/revoked");
		} else {
			strcat(invalidation_reason, "revoked");
		}
	}

	if (invalidation_reason[0]) {
		job_log(j, LOG_DEBUG, "Path %s: %s", invalidation_reason, si->what);
		job_assumes(j, runtime_close(si->fd) == 0);
		si->fd = -1; /* this will get fixed in semaphoreitem_watch() */
	}

	job_log(j, LOG_DEBUG, "Watch path modified: %s", si->what);

	if (si->why == PATH_CHANGES) {
		j->start_pending = true;
	}

	job_dispatch(j, false);
}

static void
calendarinterval_new_from_obj_dict_walk(launch_data_t obj, const char *key, void *context)
{
	struct tm *tmptm = context;
	int64_t val;

	if (LAUNCH_DATA_INTEGER != launch_data_get_type(obj)) {
		/* hack to let caller know something went wrong */
		tmptm->tm_sec = -1;
		return;
	}

	val = launch_data_get_integer(obj);

	if (strcasecmp(key, LAUNCH_JOBKEY_CAL_MINUTE) == 0) {
		tmptm->tm_min = val;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_CAL_HOUR) == 0) {
		tmptm->tm_hour = val;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_CAL_DAY) == 0) {
		tmptm->tm_mday = val;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_CAL_WEEKDAY) == 0) {
		tmptm->tm_wday = val;
	} else if (strcasecmp(key, LAUNCH_JOBKEY_CAL_MONTH) == 0) {
		tmptm->tm_mon = val;
		tmptm->tm_mon -= 1; /* 4798263 cron compatibility */
	}
}

bool
calendarinterval_new_from_obj(job_t j, launch_data_t obj)
{
	struct tm tmptm;

	memset(&tmptm, 0, sizeof(0));

	tmptm.tm_min = -1;
	tmptm.tm_hour = -1;
	tmptm.tm_mday = -1;
	tmptm.tm_wday = -1;
	tmptm.tm_mon = -1;

	if (!job_assumes(j, obj != NULL)) {
		return false;
	}

	if (LAUNCH_DATA_DICTIONARY != launch_data_get_type(obj)) {
		return false;
	}

	launch_data_dict_iterate(obj, calendarinterval_new_from_obj_dict_walk, &tmptm);

	if (tmptm.tm_sec == -1) {
		return false;
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
	ci->job = j;

	SLIST_INSERT_HEAD(&j->cal_intervals, ci, sle);
	
	calendarinterval_setalarm(j, ci);

	return true;
}

void
calendarinterval_delete(job_t j, struct calendarinterval *ci)
{
	SLIST_REMOVE(&j->cal_intervals, ci, calendarinterval, sle);
	LIST_REMOVE(ci, global_sle);

	free(ci);
}

void
calendarinterval_sanity_check(void)
{
	struct calendarinterval *ci = LIST_FIRST(&sorted_calendar_events);
	time_t now = time(NULL);

	if (ci && (ci->when_next < now)) {
		jobmgr_assumes(root_jobmgr, kill(getpid(), SIGUSR1) != -1);
	}
}

void
calendarinterval_callback(void)
{
	struct calendarinterval *ci, *ci_next;
	time_t now = time(NULL);

	LIST_FOREACH_SAFE(ci, &sorted_calendar_events, global_sle, ci_next) {
		job_t j = ci->job;

		if (ci->when_next > now) {
			break;
		}

		LIST_REMOVE(ci, global_sle);
		calendarinterval_setalarm(j, ci);

		j->start_pending = true;
		job_dispatch(j, false);
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

	for (i = 0; i < sg->fd_cnt; i++) {
		job_assumes(j, runtime_close(sg->fds[i]) != -1);
	}

	SLIST_REMOVE(&j->sockets, sg, socketgroup, sle);

	free(sg->fds);
	free(sg);
}

static void
socketgroup_kevent_mod(job_t j, struct socketgroup *sg, bool do_add)
{
	struct kevent kev[sg->fd_cnt];
	char buf[10000];
	unsigned int i, buf_off = 0;

	if (sg->junkfds) {
		return;
	}

	for (i = 0; i < sg->fd_cnt; i++) {
		EV_SET(&kev[i], sg->fds[i], EVFILT_READ, do_add ? EV_ADD : EV_DELETE, 0, 0, j);
		buf_off += snprintf(buf + buf_off, sizeof(buf) - buf_off, " %d", sg->fds[i]);
	}

	job_log(j, LOG_DEBUG, "%s Sockets:%s", do_add ? "Watching" : "Ignoring", buf);

	job_assumes(j, kevent_bulk_mod(kev, sg->fd_cnt) != -1);

	for (i = 0; i < sg->fd_cnt; i++) {
		job_assumes(j, kev[i].flags & EV_ERROR);
		errno = kev[i].data;
		job_assumes(j, kev[i].data == 0);
	}
}

void
socketgroup_ignore(job_t j, struct socketgroup *sg)
{
	socketgroup_kevent_mod(j, sg, false);
}

void
socketgroup_watch(job_t j, struct socketgroup *sg)
{
	socketgroup_kevent_mod(j, sg, true);
}

void
socketgroup_callback(job_t j)
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

	job_log(j, LOG_DEBUG, "Added environmental variable: %s=%s", k, v);

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

		SLIST_INSERT_HEAD(&j->limits, li, sle);

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
seatbelt_setup_flags(launch_data_t obj, const char *key, void *context)
{
	job_t j = context;

	if (launch_data_get_type(obj) != LAUNCH_DATA_BOOL) {
		job_log(j, LOG_WARNING, "Sandbox flag value must be boolean: %s", key);
		return;
	}

	if (launch_data_get_bool(obj) == false) {
		return;
	}

	if (strcasecmp(key, LAUNCH_JOBKEY_SANDBOX_NAMED) == 0) {
		j->seatbelt_flags |= SANDBOX_NAMED;
	}
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
	/* Yes, j->unload_at_exit and j->only_once seem the same, but they'll differ someday... */

	if ((j->unload_at_exit || j->only_once) && j->start_time != 0) {
		if (j->unload_at_exit && j->j_port) {
			return false;
		}
		job_log(j, LOG_INFO, "Exited. Was only configured to run once.");
		return true;
	} else if (j->removal_pending) {
		job_log(j, LOG_DEBUG, "Exited while removal was pending.");
		return true;
	} else if (j->mgr->shutting_down) {
		job_log(j, LOG_DEBUG, "Exited while shutdown in progress. Processes remaining: %u", total_children);
		return true;
	} else if (j->legacy_mach_job) {
		if (SLIST_EMPTY(&j->machservices)) {
			job_log(j, LOG_INFO, "Garbage collecting");
			return true;
		} else if (!j->checkedin) {
			job_log(j, LOG_WARNING, "Failed to check-in!");
			return true;
		}
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

	/*
	 * 5066316
	 *
	 * We definitely need to revisit this after Leopard ships. Please see
	 * launchctl.c for the other half of this hack.
	 */
	if (j->mgr->global_on_demand_cnt > 0 && strcmp(j->label, "com.apple.kextd") != 0) {
		return false;
	}

	if (j->start_pending) {
		job_log(j, LOG_DEBUG, "KeepAlive check: Pent-up non-IPC launch criteria.");
		return true;
	}

	if (!j->ondemand) {
		job_log(j, LOG_DEBUG, "KeepAlive check: job configured to run continuously.");
		return true;
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
		if (mach_port_get_attributes(mach_task_self(), ms->port, MACH_PORT_RECEIVE_STATUS,
					(mach_port_info_t)&status, &statusCnt) != KERN_SUCCESS) {
			continue;
		}
		if (status.mps_msgcount) {
			job_log(j, LOG_DEBUG, "KeepAlive check: job restarted due to %d queued Mach messages on service: %s",
					status.mps_msgcount, ms->name);
			return true;
		}
	}


	SLIST_FOREACH(si, &j->semaphores, sle) {
		bool wanted_state = false;
		int qdir_file_cnt;
		job_t other_j;

		switch (si->why) {
		case NETWORK_UP:
			wanted_state = true;
		case NETWORK_DOWN:
			if (network_up == wanted_state) {
				job_log(j, LOG_DEBUG, "KeepAlive: The network is %s.", wanted_state ? "up" : "down");
				return true;
			}
			break;
		case SUCCESSFUL_EXIT:
			wanted_state = true;
		case FAILED_EXIT:
			if (good_exit == wanted_state) {
				job_log(j, LOG_DEBUG, "KeepAlive: The exit state was %s.", wanted_state ? "successful" : "failure");
				return true;
			}
			break;
		case OTHER_JOB_ENABLED:
			wanted_state = true;
		case OTHER_JOB_DISABLED:
			if ((bool)job_find(si->what) == wanted_state) {
				job_log(j, LOG_DEBUG, "KeepAlive: The following job is %s: %s", wanted_state ? "enabled" : "disabled", si->what);
				return true;
			}
			break;
		case OTHER_JOB_ACTIVE:
			wanted_state = true;
		case OTHER_JOB_INACTIVE:
			if ((other_j = job_find(si->what))) {
				if ((bool)other_j->p == wanted_state) {
					job_log(j, LOG_DEBUG, "KeepAlive: The following job is %s: %s", wanted_state ? "active" : "inactive", si->what);
					return true;
				}
			}
			break;
		case PATH_EXISTS:
			wanted_state = true;
		case PATH_MISSING:
			if ((bool)(stat(si->what, &sb) == 0) == wanted_state) {
				if (si->fd != -1) {
					job_assumes(j, runtime_close(si->fd) == 0);
					si->fd = -1;
				}
				job_log(j, LOG_DEBUG, "KeepAlive: The following path %s: %s", wanted_state ? "exists" : "is missing", si->what);
				return true;
			}
			break;
		case PATH_CHANGES:
			break;
		case DIR_NOT_EMPTY:
			if (-1 == (qdir_file_cnt = dir_has_files(j, si->what))) {
				job_log_error(j, LOG_ERR, "dir_has_files(\"%s\", ...)", si->what);
			} else if (qdir_file_cnt > 0) {
				job_log(j, LOG_DEBUG, "KeepAlive: Directory is not empty: %s", si->what);
				return true;
			}
			break;
		}
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

	if (j->wait4pipe_eof && j->log_redirect_fd) {
		return true;
	}

	if (j->p) {
		return true;
	}

	if (j->priv_port_has_senders) {
		return true;
	}

	SLIST_FOREACH(ms, &j->machservices, sle) {
		if (ms->recv && ms->isActive) {
			return true;
		}
	}

	return false;
}

void
machservice_watch(job_t j, struct machservice *ms)
{
	if (ms->recv) {
		job_assumes(j, runtime_add_mport(ms->port, NULL, 0) == KERN_SUCCESS);
	}
}

void
machservice_ignore(job_t j, struct machservice *ms)
{
	job_assumes(j, runtime_remove_mport(ms->port) == KERN_SUCCESS);
}

void
machservice_resetport(job_t j, struct machservice *ms)
{
	LIST_REMOVE(ms, port_hash_sle);
	job_assumes(j, launchd_mport_close_recv(ms->port) == KERN_SUCCESS);
	job_assumes(j, launchd_mport_deallocate(ms->port) == KERN_SUCCESS);
	ms->gen_num++;
	job_assumes(j, launchd_mport_create_recv(&ms->port) == KERN_SUCCESS);
	job_assumes(j, launchd_mport_make_send(ms->port) == KERN_SUCCESS);
	LIST_INSERT_HEAD(&port_hash[HASH_PORT(ms->port)], ms, port_hash_sle);
}

struct machservice *
machservice_new(job_t j, const char *name, mach_port_t *serviceport, bool pid_local)
{
	struct machservice *ms;

	if ((ms = calloc(1, sizeof(struct machservice) + strlen(name) + 1)) == NULL) {
		return NULL;
	}

	strcpy((char *)ms->name, name);
	ms->job = j;
	ms->per_pid = pid_local;

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
	LIST_INSERT_HEAD(&j->mgr->ms_hash[hash_ms(ms->name)], ms, name_hash_sle);
	LIST_INSERT_HEAD(&port_hash[HASH_PORT(ms->port)], ms, port_hash_sle);

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
job_setup_exception_port(job_t j, task_t target_task)
{
	thread_state_flavor_t f = 0;

	if (!the_exception_server) {
		return;
	}

#if defined (__ppc__)
	f = PPC_THREAD_STATE64;
#elif defined(__i386__)
	f = x86_THREAD_STATE;
#endif

	if (target_task) {
		job_assumes(j, task_set_exception_ports(target_task, EXC_MASK_CRASH, the_exception_server,
					EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, f) == KERN_SUCCESS);
	} else if (getpid() == 1) {
		mach_port_t mhp = mach_host_self();
		job_assumes(j, host_set_exception_ports(mhp, EXC_MASK_CRASH, the_exception_server,
					EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, f) == KERN_SUCCESS);
		job_assumes(j, launchd_mport_deallocate(mhp) == KERN_SUCCESS);
	}

}

void
job_set_exeception_port(job_t j, mach_port_t port)
{
	if (!the_exception_server) {
		the_exception_server = port;
		job_setup_exception_port(j, 0);
	} else {
		job_log(j, LOG_WARNING, "The exception server is already claimed!");
	}
}

void
machservice_setup_options(launch_data_t obj, const char *key, void *context)
{
	struct machservice *ms = context;
	mach_port_t mhp = mach_host_self();
	int which_port;
	bool b;

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
				job_assumes(ms->job, (errno = task_set_special_port(mach_task_self(), which_port, ms->port)) == KERN_SUCCESS);
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
		if (strcasecmp(key, LAUNCH_JOBKEY_MACH_ENTERKERNELDEBUGGERONCLOSE) == 0) {
			ms->debug_on_close = b;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_RESETATCLOSE) == 0) {
			ms->reset = b;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_HIDEUNTILCHECKIN) == 0) {
			ms->hide = b;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_EXCEPTIONSERVER) == 0) {
			job_set_exeception_port(ms->job, ms->port);
		} else if (strcasecmp(key, LAUNCH_JOBKEY_MACH_KUNCSERVER) == 0) {
			ms->kUNCServer = b;
			job_assumes(ms->job, host_set_UNDServer(mhp, ms->port) == KERN_SUCCESS);
		}
		break;
	case LAUNCH_DATA_DICTIONARY:
		job_set_exeception_port(ms->job, ms->port);
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

	if ((ms = jobmgr_lookup_service(j->mgr, key, false, 0))) {
		job_log(j, LOG_WARNING, "Conflict with job: %s over Mach service: %s", ms->job->label, key);
		return;
	}

	if ((ms = machservice_new(j, key, &p, false)) == NULL) {
		job_log_error(j, LOG_WARNING, "Cannot add service: %s", key);
		return;
	}

	ms->isActive = false;

	if (launch_data_get_type(obj) == LAUNCH_DATA_DICTIONARY) {
		launch_data_dict_iterate(obj, machservice_setup_options, ms);
	}
}

jobmgr_t
jobmgr_do_garbage_collection(jobmgr_t jm)
{
	jobmgr_t jmi, jmn;
	job_t ji, jn;

	SLIST_FOREACH_SAFE(jmi, &jm->submgrs, sle, jmn) {
		jobmgr_do_garbage_collection(jmi);
	}

	if (!jm->shutting_down) {
		return jm;
	}

	jobmgr_log(jm, LOG_DEBUG, "Garbage collecting.");

	if (jm->hopefully_first_cnt) {
		return jm;
	}

	if (jm->parentmgr && jm->parentmgr->shutting_down && jm->parentmgr->hopefully_first_cnt) {
		return jm;
	}

	if (!jm->sent_stop_to_normal_jobs) {
		jobmgr_log(jm, LOG_DEBUG, "Asking \"normal\" jobs to exit.");

		LIST_FOREACH_SAFE(ji, &jm->jobs, sle, jn) {
			if (!job_active(ji)) {
				job_remove(ji);
			} else if (!ji->hopefully_exits_last) {
				job_stop(ji);
			}
		}

		jm->sent_stop_to_normal_jobs = true;
	}

	if (jm->normal_active_cnt) {
		return jm;
	}

	if (!jm->sent_stop_to_hopefully_last_jobs) {
		jobmgr_log(jm, LOG_DEBUG, "Asking \"hopefully last\" jobs to exit.");

		LIST_FOREACH(ji, &jm->jobs, sle) {
			if (ji->p && ji->anonymous) {
				continue;
			} else if (ji->p && job_assumes(ji, ji->hopefully_exits_last)) {
				job_stop(ji);
			}
		}

		jm->sent_stop_to_hopefully_last_jobs = true;
	}

	if (!SLIST_EMPTY(&jm->submgrs)) {
		return jm;
	}

	LIST_FOREACH(ji, &jm->jobs, sle) {
		if (!ji->anonymous) {
			return jm;
		}
	}

	jobmgr_log_stray_children(jm);
	jobmgr_remove(jm);
	return NULL;
}

void
jobmgr_log_stray_children(jobmgr_t jm)
{
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
	size_t i, kp_cnt, len = 10*1024*1024;
	struct kinfo_proc *kp;

	if (jm->parentmgr || getpid() != 1) {
		return;
	}

	if (!jobmgr_assumes(jm, (kp = malloc(len)) != NULL)) {
		return;
	}
	if (!jobmgr_assumes(jm, sysctl(mib, 3, kp, &len, NULL, 0) != -1)) {
		goto out;
	}

	kp_cnt = len / sizeof(struct kinfo_proc);

	for (i = 0; i < kp_cnt; i++) {
		pid_t p_i = kp[i].kp_proc.p_pid;
		pid_t pp_i = kp[i].kp_eproc.e_ppid;
		const char *z = kp[i].kp_proc.p_stat == SZOMB ? "zombie " : "";
		const char *n = kp[i].kp_proc.p_comm;

		if (p_i == 0 || p_i == 1) {
			continue;
		}

		jobmgr_log(jm, LOG_WARNING, "Stray %sprocess at shutdown: PID %u PPID %u %s", z, p_i, pp_i, n);

		/*
		 * The kernel team requested that I not do this for Leopard.
		 * jobmgr_assumes(jm, kill(p_i, SIGKILL) != -1);
		 */
	}

out:
	free(kp);
}

jobmgr_t 
jobmgr_parent(jobmgr_t jm)
{
	return jm->parentmgr;
}

void
job_uncork_fork(job_t j)
{
	pid_t c = j->p;

	job_log(j, LOG_DEBUG, "Uncorking the fork().");
	/* this unblocks the child and avoids a race
	 * between the above fork() and the kevent_mod() */
	job_assumes(j, write(j->forkfd, &c, sizeof(c)) == sizeof(c));
	job_assumes(j, runtime_close(j->forkfd) != -1);
	j->forkfd = 0;
}

jobmgr_t 
jobmgr_new(jobmgr_t jm, mach_port_t requestorport, mach_port_t transfer_port, bool sflag, const char *name)
{
	mach_msg_size_t mxmsgsz;
	job_t bootstrapper = NULL;
	jobmgr_t jmr;

	launchd_assert(offsetof(struct jobmgr_s, kqjobmgr_callback) == 0);

	if (jm && requestorport == MACH_PORT_NULL) {
		jobmgr_log(jm, LOG_ERR, "Mach sub-bootstrap create request requires a requester port");
		return NULL;
	}

	jmr = calloc(1, sizeof(struct jobmgr_s) + (name ? (strlen(name) + 1) : 128));
	
	if (jmr == NULL) {
		return NULL;
	}

	jmr->kqjobmgr_callback = jobmgr_callback;
	strcpy(jmr->name, name ? name : "Under construction");

	jmr->req_port = requestorport;

	if ((jmr->parentmgr = jm)) {
		SLIST_INSERT_HEAD(&jm->submgrs, jmr, sle);
	}

	if (jm && !jobmgr_assumes(jmr, launchd_mport_notify_req(jmr->req_port, MACH_NOTIFY_DEAD_NAME) == KERN_SUCCESS)) {
		goto out_bad;
	}

	if (transfer_port != MACH_PORT_NULL) {
		jobmgr_assumes(jmr, jm != NULL);
		jmr->jm_port = transfer_port;
	} else if (!jm && getpid() != 1) {
		char *trusted_fd = getenv(LAUNCHD_TRUSTED_FD_ENV);
		name_t service_buf;

		snprintf(service_buf, sizeof(service_buf), "com.apple.launchd.peruser.%u", getuid());

		if (!jobmgr_assumes(jmr, bootstrap_check_in(bootstrap_port, service_buf, &jmr->jm_port) == 0)) {
			goto out_bad;
		}

		if (trusted_fd) {
			int dfd, lfd = strtol(trusted_fd, NULL, 10);

			if ((dfd = dup(lfd)) >= 0) {
				jobmgr_assumes(jmr, runtime_close(dfd) != -1);
				jobmgr_assumes(jmr, runtime_close(lfd) != -1);
			}

			unsetenv(LAUNCHD_TRUSTED_FD_ENV);
		}

		inherited_bootstrap_port = bootstrap_port;
		/* cut off the Libc cache, we don't want to deadlock against ourself */
		bootstrap_port = MACH_PORT_NULL;
		/* We set this explicitly as we start each child */
		launchd_assert(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);
	} else if (!jobmgr_assumes(jmr, launchd_mport_create_recv(&jmr->jm_port) == KERN_SUCCESS)) {
		goto out_bad;
	}

	if (!name) {
		sprintf(jmr->name, "%u", MACH_PORT_INDEX(jmr->jm_port));
	}

	/* Sigh... at the moment, MIG has maxsize == sizeof(reply union) */
	mxmsgsz = sizeof(union __RequestUnion__job_mig_protocol_vproc_subsystem);
	if (job_mig_protocol_vproc_subsystem.maxsize > mxmsgsz) {
		mxmsgsz = job_mig_protocol_vproc_subsystem.maxsize;
	}

	if (!jm) {
		jobmgr_assumes(jmr, kevent_mod(SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, jmr) != -1);
		jobmgr_assumes(jmr, kevent_mod(SIGUSR1, EVFILT_SIGNAL, EV_ADD, 0, 0, jmr) != -1);
		jobmgr_assumes(jmr, kevent_mod(0, EVFILT_FS, EV_ADD, VQ_MOUNT|VQ_UNMOUNT|VQ_UPDATE, 0, jmr) != -1);
	}

	if (name) {
		bootstrapper = jobmgr_init_session(jmr, name, sflag);
	}

	if (!bootstrapper || !bootstrapper->weird_bootstrap) {
		if (!jobmgr_assumes(jmr, runtime_add_mport(jmr->jm_port, protocol_vproc_server, mxmsgsz) == KERN_SUCCESS)) {
			goto out_bad;
		}
	}

	jobmgr_log(jmr, LOG_DEBUG, "Created job manager%s%s", jm ? " with parent: " : ".", jm ? jm->name : "");

	if (bootstrapper) {
		jobmgr_assumes(jmr, job_dispatch(bootstrapper, true) != NULL);
	}

	return jmr;

out_bad:
	if (jmr) {
		jobmgr_remove(jmr);
	}
	return NULL;
}

job_t
jobmgr_init_session(jobmgr_t jm, const char *session_type, bool sflag)
{
	const char *bootstrap_tool[] = { "/bin/launchctl", "bootstrap", "-S", session_type, sflag ? "-s" : NULL, NULL };
	char thelabel[1000];
	job_t bootstrapper;

	snprintf(thelabel, sizeof(thelabel), "com.apple.launchctl.%s", session_type);
	bootstrapper = job_new(jm, thelabel, NULL, bootstrap_tool);
	if (jobmgr_assumes(jm, bootstrapper != NULL) && (jm->parentmgr || getuid())) {
		char buf[100];

		/* <rdar://problem/5042202> launchd-201: can't ssh in with AFP OD account (hangs) */
		snprintf(buf, sizeof(buf), "0x%X:0:0", getuid());
		envitem_new(bootstrapper, "__CF_USER_TEXT_ENCODING", buf, false);
		bootstrapper->weird_bootstrap = true;
		jobmgr_assumes(jm, job_setup_machport(bootstrapper));
	}

	jm->session_initialized = true;

	return bootstrapper;
}

jobmgr_t
jobmgr_delete_anything_with_port(jobmgr_t jm, mach_port_t port)
{
	struct machservice *ms, *next_ms;
	jobmgr_t jmi, jmn;

	/* Mach ports, unlike Unix descriptors, are reference counted. In other
	 * words, when some program hands us a second or subsequent send right
	 * to a port we already have open, the Mach kernel gives us the same
	 * port number back and increments an reference count associated with
	 * the port. This forces us, when discovering that a receive right at
	 * the other end has been deleted, to wander all of our objects to see
	 * what weird places clients might have handed us the same send right
	 * to use.
	 */

	if (jm == root_jobmgr) {
		LIST_FOREACH_SAFE(ms, &port_hash[HASH_PORT(port)], port_hash_sle, next_ms) {
			if (ms->port == port) {
				machservice_delete(ms->job, ms, true);
			}
		}
	}

	SLIST_FOREACH_SAFE(jmi, &jm->submgrs, sle, jmn) {
		jobmgr_delete_anything_with_port(jmi, port);
	}

	if (jm->req_port == port) {
		jobmgr_log(jm, LOG_DEBUG, "Request port died: 0x%x", port);
		return jobmgr_shutdown(jm);
	}

	return jm;
}

struct machservice *
jobmgr_lookup_service(jobmgr_t jm, const char *name, bool check_parent, pid_t target_pid)
{
	struct machservice *ms;

	if (target_pid) {
		jobmgr_assumes(jm, !check_parent);
	}

	LIST_FOREACH(ms, &jm->ms_hash[hash_ms(name)], name_hash_sle) {
		if ((target_pid && ms->per_pid && ms->job->p == target_pid) || (!target_pid && !ms->per_pid)) {
			if (strcmp(name, ms->name) == 0) {
				return ms;
			}
		}
	}

	if (jm->parentmgr == NULL) {
		return NULL;
	}

	if (!check_parent) {
		return NULL;
	}

	return jobmgr_lookup_service(jm->parentmgr, name, true, 0);
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
machservice_delete(job_t j, struct machservice *ms, bool port_died)
{
	if (ms->debug_on_close) {
		job_log(j, LOG_NOTICE, "About to enter kernel debugger because of Mach port: 0x%x", ms->port);
		job_assumes(j, host_reboot(mach_host_self(), HOST_REBOOT_DEBUGGER) == KERN_SUCCESS);
	}

	if (ms->recv && job_assumes(j, !ms->isActive)) {
		job_assumes(j, launchd_mport_close_recv(ms->port) == KERN_SUCCESS);
	}

	job_assumes(j, launchd_mport_deallocate(ms->port) == KERN_SUCCESS);

	if (ms->port == the_exception_server) {
		the_exception_server = 0;
	}

	job_log(j, LOG_INFO, "Mach service deleted%s: %s", port_died ? " (port died)" : "", ms->name);

	SLIST_REMOVE(&j->machservices, ms, machservice, sle);
	LIST_REMOVE(ms, name_hash_sle);
	LIST_REMOVE(ms, port_hash_sle);

	free(ms);
}

void
machservice_request_notifications(struct machservice *ms)
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
job_ack_port_destruction(mach_port_t p)
{
	struct machservice *ms;

	LIST_FOREACH(ms, &port_hash[HASH_PORT(p)], port_hash_sle) {
		if (ms->port == p) {
			break;
		}
	}

	if (!ms) {
		return false;
	}

	ms->isActive = false;

	if (ms->reset) {
		machservice_resetport(ms->job, ms);
	}

	job_log(ms->job, LOG_DEBUG, "Receive right returned to us: %s", ms->name);
	job_dispatch(ms->job, false);
	return true;
}

void
job_ack_no_senders(job_t j)
{
	j->priv_port_has_senders = false;

	job_assumes(j, launchd_mport_close_recv(j->j_port) == KERN_SUCCESS);
	j->j_port = 0;

	job_log(j, LOG_DEBUG, "No more senders on privileged Mach bootstrap port");

	job_dispatch(j, false);
}

jobmgr_t 
job_get_bs(job_t j)
{
	if (job_assumes(j, j->mgr != NULL)) {
		return j->mgr;
	}

	return NULL;
}

bool
job_is_anonymous(job_t j)
{
	return j->anonymous;
}

pid_t
job_get_pid(job_t j)
{
	return j->p;
}

void
job_force_sampletool(job_t j)
{
	struct stat sb;
	char logfile[PATH_MAX];
	char pidstr[100];
	char *sample_args[] = { "sample", pidstr, "1", "-mayDie", "-file", logfile, NULL };
	char *contents = NULL;
	int logfile_fd = -1;
	int console_fd = -1;
	int wstatus;
	pid_t sp;

	if (!debug_shutdown_hangs) {
		return;
	}
	
	snprintf(pidstr, sizeof(pidstr), "%u", j->p);
	snprintf(logfile, sizeof(logfile), SHUTDOWN_LOG_DIR "/%s-%u.sample.txt", j->label, j->p);

	if (!job_assumes(j, unlink(logfile) != -1 || errno == ENOENT)) {
		goto out;
	}

	/*
	 * This will stall launchd for as long as the 'sample' tool runs.
	 *
	 * We didn't give the 'sample' tool a bootstrap port, so it therefore
	 * can't deadlock against launchd.
	 */
	if (!job_assumes(j, (errno = posix_spawnp(&sp, sample_args[0], NULL, NULL, sample_args, environ)) == 0)) {
		goto out;
	}

	job_log(j, LOG_DEBUG, "Waiting for 'sample' to finish.");

	if (!job_assumes(j, waitpid(sp, &wstatus, 0) != -1)) {
		goto out;
	}

	/*
	 * This won't work if the VFS or filesystems are sick:
	 * sync();
	 */

	if (!job_assumes(j, WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)) {
		goto out;
	}

	if (!job_assumes(j, (logfile_fd = open(logfile, O_RDONLY|O_NOCTTY)) != -1)) {
		goto out;
	}

	if (!job_assumes(j, (console_fd = open(_PATH_CONSOLE, O_WRONLY|O_APPEND|O_NOCTTY)) != -1)) {
		goto out;
	}

	if (!job_assumes(j, fstat(logfile_fd, &sb) != -1)) {
		goto out;
	}

	contents = malloc(sb.st_size);

	if (!job_assumes(j, contents != NULL)) {
		goto out;
	}

	if (!job_assumes(j, read(logfile_fd, contents, sb.st_size) == sb.st_size)) {
		goto out;
	}

	job_assumes(j, write(console_fd, contents, sb.st_size) == sb.st_size);

out:
	if (contents) {
		free(contents);
	}

	if (logfile_fd != -1) {
		job_assumes(j, fcntl(logfile_fd, F_FULLFSYNC, 0) != -1);
		job_assumes(j, runtime_close(logfile_fd) != -1);
	}

	if (console_fd != -1) {
		job_assumes(j, runtime_close(console_fd) != -1);
	}

	job_log(j, LOG_DEBUG, "Finished sampling.");
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

	si->fd = -1;
	si->why = why;

	if (what) {
		strcpy(si->what, what);
	}

	SLIST_INSERT_HEAD(&j->semaphores, si, sle);

	return true;
}

void
semaphoreitem_delete(job_t j, struct semaphoreitem *si)
{
	SLIST_REMOVE(&j->semaphores, si, semaphoreitem, sle);

	if (si->fd != -1) {
		job_assumes(j, runtime_close(si->fd) != -1);
	}

	free(si);
}

void
semaphoreitem_setup_dict_iter(launch_data_t obj, const char *key, void *context)
{
	struct semaphoreitem_dict_iter_context *sdic = context;
	semaphore_reason_t why;

	why = launch_data_get_bool(obj) ? sdic->why_true : sdic->why_false;

	semaphoreitem_new(sdic->j, why, key);
}

void
semaphoreitem_setup(launch_data_t obj, const char *key, void *context)
{
	struct semaphoreitem_dict_iter_context sdic = { context, 0, 0 };
	job_t j = context;
	semaphore_reason_t why;

	switch (launch_data_get_type(obj)) {
	case LAUNCH_DATA_BOOL:
		if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_NETWORKSTATE) == 0) {
			why = launch_data_get_bool(obj) ? NETWORK_UP : NETWORK_DOWN;
			semaphoreitem_new(j, why, NULL);
		} else if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_SUCCESSFULEXIT) == 0) {
			why = launch_data_get_bool(obj) ? SUCCESSFUL_EXIT : FAILED_EXIT;
			semaphoreitem_new(j, why, NULL);
			j->start_pending = true;
		} else {
			job_assumes(j, false);
		}
		break;
	case LAUNCH_DATA_DICTIONARY:
		if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_PATHSTATE) == 0) {
			sdic.why_true = PATH_EXISTS;
			sdic.why_false = PATH_MISSING;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_OTHERJOBACTIVE) == 0) {
			sdic.why_true = OTHER_JOB_ACTIVE;
			sdic.why_false = OTHER_JOB_INACTIVE;
		} else if (strcasecmp(key, LAUNCH_JOBKEY_KEEPALIVE_OTHERJOBENABLED) == 0) {
			sdic.why_true = OTHER_JOB_ENABLED;
			sdic.why_false = OTHER_JOB_DISABLED;
		} else {
			job_assumes(j, false);
			break;
		}

		launch_data_dict_iterate(obj, semaphoreitem_setup_dict_iter, &sdic);
		break;
	default:
		job_assumes(j, false);
		break;
	}
}

void
jobmgr_dispatch_all_semaphores(jobmgr_t jm)
{
	jobmgr_t jmi, jmn;
	job_t ji, jn;


	SLIST_FOREACH_SAFE(jmi, &jm->submgrs, sle, jmn) {
		jobmgr_dispatch_all_semaphores(jmi);
	}

	LIST_FOREACH_SAFE(ji, &jm->jobs, sle, jn) {
		if (!SLIST_EMPTY(&ji->semaphores)) {
			job_dispatch(ji, false);
		}
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

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	runtime_get_caller_creds(&ldc);

	job_log(j, LOG_DEBUG, "Server create attempt: %s", server_cmd);

#define LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	/* XXX - This code should go away once the per session launchd is integrated with the rest of the system */
#ifdef LET_MERE_MORTALS_ADD_SERVERS_TO_PID1
	if (getpid() == 1) {
		if (ldc.euid && server_uid && (ldc.euid != server_uid)) {
			job_log(j, LOG_WARNING, "Server create: \"%s\": Will run as UID %d, not UID %d as they told us to",
					server_cmd, ldc.euid, server_uid);
			server_uid = ldc.euid;
		}
	} else
#endif
	if (getuid()) {
		if (server_uid != getuid()) {
			job_log(j, LOG_WARNING, "Server create: \"%s\": As UID %d, we will not be able to switch to UID %d",
					server_cmd, getuid(), server_uid);
		}
		server_uid = 0; /* zero means "do nothing" */
	}

	js = job_new_via_mach_init(j, server_cmd, server_uid, on_demand);

	if (js == NULL) {
		return BOOTSTRAP_NO_MEMORY;
	}

	*server_portp = js->j_port;
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_send_signal(job_t j, name_t targetlabel, int sig)
{
	struct ldcred ldc;
	job_t otherj;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	runtime_get_caller_creds(&ldc);

	if (ldc.euid != 0 && ldc.euid != getuid()) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (!(otherj = job_find(targetlabel))) {
		return BOOTSTRAP_UNKNOWN_SERVICE;
	}

	if (otherj->p) {
		job_assumes(j, kill(otherj->p, sig) != -1);
	}

	return 0;
}

kern_return_t
job_mig_swap_complex(job_t j, vproc_gsk_t inkey, vproc_gsk_t outkey,
		vm_offset_t inval, mach_msg_type_number_t invalCnt,
		vm_offset_t *outval, mach_msg_type_number_t *outvalCnt) 
{
	const char *action;
	launch_data_t input_obj, output_obj;
	size_t data_offset = 0;
	size_t packed_size;
	struct ldcred ldc;

	runtime_get_caller_creds(&ldc);

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (inkey && ldc.euid && ldc.euid != getuid()) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (inkey && outkey && !job_assumes(j, inkey == outkey)) {
		return 1;
	}

	if (inkey && outkey) {
		action = "Swapping";
	} else if (inkey) {
		action = "Setting";
	} else {
		action = "Getting";
	}

	job_log(j, LOG_DEBUG, "%s key: %u", action, inkey ? inkey : outkey);

	*outvalCnt = 20 * 1024 * 1024;
	mig_allocate(outval, *outvalCnt);
	if (!job_assumes(j, *outval != 0)) {
		return 1;
	}

	if (invalCnt && !job_assumes(j, (input_obj = launch_data_unpack((void *)inval, invalCnt, NULL, 0, &data_offset, NULL)) != NULL)) {
		goto out_bad;
	}

	switch (outkey) {
	case VPROC_GSK_ENVIRONMENT:
		if (!job_assumes(j, (output_obj = launch_data_alloc(LAUNCH_DATA_DICTIONARY)))) {
			goto out_bad;
		}
		jobmgr_export_env_from_other_jobs(j->mgr, output_obj);
		if (!job_assumes(j, launch_data_pack(output_obj, (void *)*outval, *outvalCnt, NULL, NULL) != 0)) {
			goto out_bad;
		}
		launch_data_free(output_obj);
		break;
	case VPROC_GSK_ALLJOBS:
		if (!job_assumes(j, (output_obj = job_export_all()) != NULL)) {
			goto out_bad;
		}
		ipc_revoke_fds(output_obj);
		packed_size = launch_data_pack(output_obj, (void *)*outval, *outvalCnt, NULL, NULL);
		if (!job_assumes(j, packed_size != 0)) {
			goto out_bad;
		}
		launch_data_free(output_obj);
		break;
	case 0:
		mig_deallocate(*outval, *outvalCnt);
		*outval = 0;
		*outvalCnt = 0;
		break;
	default:
		goto out_bad;
	}

	if (invalCnt) switch (inkey) {
	case VPROC_GSK_ENVIRONMENT:
		job_assumes(j, false);
		break;
	case 0:
		break;
	default:
		goto out_bad;
	}

	mig_deallocate(inval, invalCnt);

	return 0;

out_bad:
	if (*outval) {
		mig_deallocate(*outval, *outvalCnt);
	}
	return 1;
}

kern_return_t
job_mig_swap_integer(job_t j, vproc_gsk_t inkey, vproc_gsk_t outkey, int64_t inval, int64_t *outval)
{
	const char *action;
	kern_return_t kr = 0;
	struct ldcred ldc;
	int oldmask;

	runtime_get_caller_creds(&ldc);

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (inkey && ldc.euid && ldc.euid != getuid()) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (inkey && outkey && !job_assumes(j, inkey == outkey)) {
		return 1;
	}

	if (inkey && outkey) {
		action = "Swapping";
	} else if (inkey) {
		action = "Setting";
	} else {
		action = "Getting";
	}

	job_log(j, LOG_DEBUG, "%s key: %u", action, inkey ? inkey : outkey);

	switch (outkey) {
	case VPROC_GSK_LAST_EXIT_STATUS:
		*outval = j->last_exit_status;
		break;
	case VPROC_GSK_MGR_UID:
		*outval = getuid();
		break;
	case VPROC_GSK_MGR_PID:
		*outval = getpid();
		break;
	case VPROC_GSK_IS_MANAGED:
		*outval = j->anonymous ? 0 : 1;
		break;
	case VPROC_GSK_BASIC_KEEPALIVE:
		*outval = !j->ondemand;
		break;
	case VPROC_GSK_START_INTERVAL:
		*outval = j->start_interval;
		break;
	case VPROC_GSK_IDLE_TIMEOUT:
		*outval = j->timeout;
		break;
	case VPROC_GSK_EXIT_TIMEOUT:
		*outval = j->exit_timeout;
		break;
	case VPROC_GSK_GLOBAL_LOG_MASK:
		oldmask = runtime_setlogmask(LOG_UPTO(LOG_DEBUG));
		*outval = oldmask;
		runtime_setlogmask(oldmask);
		break;
	case VPROC_GSK_GLOBAL_UMASK:
		oldmask = umask(0);
		*outval = oldmask;
		umask(oldmask);
		break;
	case 0:
		*outval = 0;
		break;
	default:
		kr = 1;
		break;
	}

	switch (inkey) {
	case VPROC_GSK_GLOBAL_ON_DEMAND:
		kr = job_set_global_on_demand(j, (bool)inval) ? 0 : 1;
		break;
	case VPROC_GSK_BASIC_KEEPALIVE:
		j->ondemand = !inval;
		break;
	case VPROC_GSK_START_INTERVAL:
		if ((unsigned int)inval > 0) {
			j->start_interval = inval;
			job_assumes(j, kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, j->start_interval, j) != -1);
		} else if (j->start_interval) {
			job_assumes(j, kevent_mod((uintptr_t)&j->start_interval, EVFILT_TIMER, EV_DELETE, 0, 0, NULL) != -1);
			j->start_interval = 0;
		}
		break;
	case VPROC_GSK_IDLE_TIMEOUT:
		if ((unsigned int)inval > 0) {
			j->timeout = inval;
		}
		break;
	case VPROC_GSK_EXIT_TIMEOUT:
		if ((unsigned int)inval > 0) {
			j->exit_timeout = inval;
		}
		break;
	case VPROC_GSK_GLOBAL_LOG_MASK:
		runtime_setlogmask(inval);
		break;
	case VPROC_GSK_GLOBAL_UMASK:
		umask(inval);
		break;
	case 0:
		break;
	default:
		kr = 1;
		break;
	}

	return kr;
}

kern_return_t
job_mig_post_fork_ping(job_t j, task_t child_task)
{
	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	job_log(j, LOG_DEBUG, "Post fork ping.");

	job_setup_exception_port(j, child_task);

	job_assumes(j, launchd_mport_deallocate(child_task) == KERN_SUCCESS);

	return 0;
}

kern_return_t
job_mig_reboot2(job_t j, uint64_t flags)
{
	char who_started_the_reboot[2048] = "";
	struct kinfo_proc kp;
	struct ldcred ldc;
	pid_t pid_to_log;

	if (getpid() != 1) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	runtime_get_caller_creds(&ldc);

	if (ldc.euid) {
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	for (pid_to_log = ldc.pid; pid_to_log; pid_to_log = kp.kp_eproc.e_ppid) {
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid_to_log };
		size_t who_offset, len = sizeof(kp);

		if (!job_assumes(j, sysctl(mib, 4, &kp, &len, NULL, 0) != -1)) {
			return 1;
		}

		who_offset = strlen(who_started_the_reboot);
		snprintf(who_started_the_reboot + who_offset, sizeof(who_started_the_reboot) - who_offset,
				" %s[%u]%s", kp.kp_proc.p_comm, pid_to_log, kp.kp_eproc.e_ppid ? " ->" : "");
	}

	root_jobmgr->reboot_flags = (int)flags;

	launchd_shutdown();

	job_log(j, LOG_DEBUG, "reboot2() initiated by:%s", who_started_the_reboot);

	return 0;
}

kern_return_t
job_mig_getsocket(job_t j, name_t spr)
{
	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	ipc_server_init();

	if (!sockpath) {
		return BOOTSTRAP_NO_MEMORY;
	}

	strncpy(spr, sockpath, sizeof(name_t));
	
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_log(job_t j, int pri, int err, logmsg_t msg)
{
	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if ((errno = err)) {
		job_log_error(j, pri, "%s", msg);
	} else {
		job_log(j, pri, "%s", msg);
	}

	return 0;
}

void
ensure_root_bkgd_setup(void)
{
	if (background_jobmgr || getpid() != 1) {
		return;
	}

	if (!jobmgr_assumes(root_jobmgr, (background_jobmgr = jobmgr_new(root_jobmgr, mach_task_self(), MACH_PORT_NULL, false, VPROCMGR_SESSION_BACKGROUND)) != NULL)) {
		return;
	}

	background_jobmgr->req_port = 0;
	jobmgr_assumes(root_jobmgr, launchd_mport_make_send(background_jobmgr->jm_port) == KERN_SUCCESS);
}

kern_return_t
job_mig_lookup_per_user_context(job_t j, uid_t which_user, mach_port_t *up_cont)
{
	struct ldcred ldc;
	job_t ji;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	job_log(j, LOG_DEBUG, "Looking up per user launchd for UID: %u", which_user);

	runtime_get_caller_creds(&ldc);

	if (getpid() != 1) {
		job_log(j, LOG_ERR, "Only PID 1 supports per user launchd lookups.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (ldc.euid || ldc.uid) {
		which_user = ldc.euid ? ldc.euid : ldc.uid;
	}

	*up_cont = MACH_PORT_NULL;

	if (which_user == 0) {
		ensure_root_bkgd_setup();

		*up_cont = background_jobmgr->jm_port;

		return 0;
	}

	LIST_FOREACH(ji, &root_jobmgr->jobs, sle) {
		if (!ji->per_user) {
			continue;
		}
		if (ji->mach_uid != which_user) {
			continue;
		}
		if (SLIST_EMPTY(&ji->machservices)) {
			continue;
		}
		if (!SLIST_FIRST(&ji->machservices)->per_user_hack) {
			continue;
		}
		break;
	}

	if (ji == NULL) {
		struct machservice *ms;
		char lbuf[1024];

		job_log(j, LOG_DEBUG, "Creating per user launchd job for UID: %u", which_user);

		sprintf(lbuf, "com.apple.launchd.peruser.%u", which_user);

		ji = job_new(root_jobmgr, lbuf, "/sbin/launchd", NULL);

		if (ji == NULL) {
			return BOOTSTRAP_NO_MEMORY;
		}

		ji->mach_uid = which_user;
		ji->per_user = true;

		if ((ms = machservice_new(ji, lbuf, up_cont, false)) == NULL) {
			job_remove(ji);
			return BOOTSTRAP_NO_MEMORY;
		}

		ms->per_user_hack = true;
		ms->hide = true;

		ji = job_dispatch(ji, false);
	} else {
		job_log(j, LOG_DEBUG, "Per user launchd job found for UID: %u", which_user);
	}

	if (job_assumes(j, ji != NULL)) {
		*up_cont = machservice_port(SLIST_FIRST(&ji->machservices));
	}

	return 0;
}

kern_return_t
job_mig_check_in(job_t j, name_t servicename, mach_port_t *serviceportp)
{
	static pid_t last_warned_pid = 0;
	struct machservice *ms;
	struct ldcred ldc;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	runtime_get_caller_creds(&ldc);

	ms = jobmgr_lookup_service(j->mgr, servicename, true, 0);

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

	machservice_request_notifications(ms);

	job_log(j, LOG_INFO, "Check-in of service: %s", servicename);

	*serviceportp = machservice_port(ms);
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_register2(job_t j, name_t servicename, mach_port_t serviceport, uint64_t flags)
{
	struct machservice *ms;
	struct ldcred ldc;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	runtime_get_caller_creds(&ldc);

#if 0
	job_log(j, LOG_APPLEONLY, "bootstrap_register() is deprecated. Service: %s", servicename);
#endif

	job_log(j, LOG_DEBUG, "%sMach service registration attempt: %s", flags & BOOTSTRAP_PER_PID_SERVICE ? "Per PID " : "", servicename);

	/*
	 * From a per-user/session launchd's perspective, SecurityAgent (UID
	 * 92) is a rogue application (not our UID, not root and not a child of
	 * us). We'll have to reconcile this design friction at a later date.
	 */
	if (j->anonymous && job_get_bs(j)->parentmgr == NULL && ldc.uid != 0 && ldc.uid != getuid() && ldc.uid != 92) {
		if (getpid() == 1) {
			return VPROC_ERR_TRY_PER_USER;
		} else {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
	}
	
	ms = jobmgr_lookup_service(j->mgr, servicename, false, flags & BOOTSTRAP_PER_PID_SERVICE ? ldc.pid : 0);

	if (ms) {
		if (machservice_job(ms) != j) {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
		if (machservice_active(ms)) {
			job_log(j, LOG_DEBUG, "Mach service registration failed. Already active: %s", servicename);
			return BOOTSTRAP_SERVICE_ACTIVE;
		}
		job_checkin(j);
		machservice_delete(j, ms, false);
	}

	if (serviceport != MACH_PORT_NULL) {
		if ((ms = machservice_new(j, servicename, &serviceport, flags & BOOTSTRAP_PER_PID_SERVICE ? true : false))) {
			machservice_request_notifications(ms);
		} else {
			return BOOTSTRAP_NO_MEMORY;
		}
	}

	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_look_up2(job_t j, name_t servicename, mach_port_t *serviceportp, mach_msg_type_name_t *ptype, pid_t target_pid, uint64_t flags)
{
	struct machservice *ms;
	struct ldcred ldc;
	kern_return_t kr;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	runtime_get_caller_creds(&ldc);

	if (getpid() == 1 && j->anonymous && job_get_bs(j)->parentmgr == NULL && ldc.uid != 0 && ldc.euid != 0) {
		return VPROC_ERR_TRY_PER_USER;
	}

	if (!mspolicy_check(j, servicename, flags & BOOTSTRAP_PER_PID_SERVICE)) {
		job_log(j, LOG_NOTICE, "Policy denied Mach service lookup: %s", servicename);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (flags & BOOTSTRAP_PER_PID_SERVICE) {
		ms = jobmgr_lookup_service(j->mgr, servicename, false, target_pid);
	} else {
		ms = jobmgr_lookup_service(j->mgr, servicename, true, 0);
	}

	if (ms && machservice_hidden(ms) && !job_active(machservice_job(ms))) {
		ms = NULL;
	} else if (ms && ms->per_user_hack) {
		ms = NULL;
	}

	if (ms) {
		launchd_assumes(machservice_port(ms) != MACH_PORT_NULL);
		job_log(j, LOG_DEBUG, "%sMach service lookup: %s", flags & BOOTSTRAP_PER_PID_SERVICE ? "Per PID " : "", servicename);
#if 0
		/* After Leopard ships, we should enable this */
		if (j->lastlookup == ms && j->lastlookup_gennum == ms->gen_num && !j->per_user) {
			ms->bad_perf_cnt++;
			job_log(j, LOG_APPLEONLY, "Performance opportunity: Number of bootstrap_lookup(... \"%s\" ...) calls that should have been cached: %llu",
					servicename, ms->bad_perf_cnt);
		}
		j->lastlookup = ms;
		j->lastlookup_gennum = ms->gen_num;
#endif
		*serviceportp = machservice_port(ms);
		*ptype = MACH_MSG_TYPE_COPY_SEND;
		kr = BOOTSTRAP_SUCCESS;
	} else if (!(flags & BOOTSTRAP_PER_PID_SERVICE) && (inherited_bootstrap_port != MACH_PORT_NULL)) {
		job_log(j, LOG_DEBUG, "Mach service lookup forwarded: %s", servicename);
		*ptype = MACH_MSG_TYPE_MOVE_SEND;
		kr = bootstrap_look_up(inherited_bootstrap_port, servicename, serviceportp);
	} else if (getpid() == 1 && j->anonymous && ldc.euid >= 500 && strcasecmp(job_get_bs(j)->name, VPROCMGR_SESSION_LOGINWINDOW) == 0) {
		/*
		 * 5240036 Should start background session when a lookup of CCacheServer occurs
		 *
		 * This is a total hack. We sniff out loginwindow session, and attempt to guess what it is up to.
		 * If we find a EUID that isn't root, we force it over to the per-user context.
		 */
		return VPROC_ERR_TRY_PER_USER;
	} else {
		job_log(j, LOG_DEBUG, "%sMach service lookup failed: %s", flags & BOOTSTRAP_PER_PID_SERVICE ? "Per PID " : "", servicename);
		kr = BOOTSTRAP_UNKNOWN_SERVICE;
	}

	return kr;
}

kern_return_t
job_mig_parent(job_t j, mach_port_t *parentport, mach_msg_type_name_t *pptype)
{
	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	job_log(j, LOG_DEBUG, "Requested parent bootstrap port");
	jobmgr_t jm = j->mgr;

	*pptype = MACH_MSG_TYPE_MAKE_SEND;

	if (jobmgr_parent(jm)) {
		*parentport = jobmgr_parent(jm)->jm_port;
	} else if (MACH_PORT_NULL == inherited_bootstrap_port) {
		*parentport = jm->jm_port;
	} else {
		*pptype = MACH_MSG_TYPE_COPY_SEND;
		*parentport = inherited_bootstrap_port;
	}
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_info(job_t j, name_array_t *servicenamesp, unsigned int *servicenames_cnt,
		bootstrap_status_array_t *serviceactivesp, unsigned int *serviceactives_cnt)
{
	name_array_t service_names = NULL;
	bootstrap_status_array_t service_actives = NULL;
	unsigned int cnt = 0, cnt2 = 0;
	struct machservice *ms;
	jobmgr_t jm;
	job_t ji;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	jm = j->mgr;

	LIST_FOREACH(ji, &jm->jobs, sle) {
		SLIST_FOREACH(ms, &ji->machservices, sle) {
			if (!ms->per_pid) {
				cnt++;
			}
		}
	}

	if (cnt == 0) {
		goto out;
	}

	mig_allocate((vm_address_t *)&service_names, cnt * sizeof(service_names[0]));
	if (!launchd_assumes(service_names != NULL)) {
		goto out_bad;
	}

	mig_allocate((vm_address_t *)&service_actives, cnt * sizeof(service_actives[0]));
	if (!launchd_assumes(service_actives != NULL)) {
		goto out_bad;
	}

	LIST_FOREACH(ji, &jm->jobs, sle) {
		SLIST_FOREACH(ms, &ji->machservices, sle) {
			if (!ms->per_pid) {
				strlcpy(service_names[cnt2], machservice_name(ms), sizeof(service_names[0]));
				service_actives[cnt2] = machservice_status(ms);
				cnt2++;
			}
		}
	}

	launchd_assumes(cnt == cnt2);

out:
	*servicenamesp = service_names;
	*serviceactivesp = service_actives;
	*servicenames_cnt = *serviceactives_cnt = cnt;

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (service_names) {
		mig_deallocate((vm_address_t)service_names, cnt * sizeof(service_names[0]));
	}
	if (service_actives) {
		mig_deallocate((vm_address_t)service_actives, cnt * sizeof(service_actives[0]));
	}

	return BOOTSTRAP_NO_MEMORY;
}

void
job_reparent_hack(job_t j, const char *where)
{
	jobmgr_t jmi, jmi2;

	ensure_root_bkgd_setup();

	/* NULL is only passed for our custom API for LaunchServices. If that is the case, we do magic. */
	if (where == NULL) {
		if (strcasecmp(j->mgr->name, VPROCMGR_SESSION_LOGINWINDOW) == 0) {
			where = VPROCMGR_SESSION_LOGINWINDOW;
		} else {
			where = VPROCMGR_SESSION_AQUA;
		}
	}

	if (strcasecmp(j->mgr->name, where) == 0) {
		return;
	}

	SLIST_FOREACH(jmi, &root_jobmgr->submgrs, sle) {
		if (strcasecmp(jmi->name, where) == 0) {
			goto jm_found;
		} else if (strcasecmp(jmi->name, VPROCMGR_SESSION_BACKGROUND) == 0 && getpid() == 1) {
			SLIST_FOREACH(jmi2, &jmi->submgrs, sle) {
				if (strcasecmp(jmi2->name, where) == 0) {
					jmi = jmi2;
					goto jm_found;
				}
			}
		}
	}

jm_found:
	if (job_assumes(j, jmi != NULL)) {
		struct machservice *msi;

		SLIST_FOREACH(msi, &j->machservices, sle) {
			LIST_REMOVE(msi, name_hash_sle);
		}

		LIST_REMOVE(j, sle);
		LIST_INSERT_HEAD(&jmi->jobs, j, sle);
		j->mgr = jmi;

		SLIST_FOREACH(msi, &j->machservices, sle) {
			LIST_INSERT_HEAD(&j->mgr->ms_hash[hash_ms(msi->name)], msi, name_hash_sle);
		}
	}
}

kern_return_t
job_mig_move_subset(job_t j, mach_port_t target_subset, name_t session_type)
{
	mach_msg_type_number_t l2l_i, l2l_port_cnt = 0;
	mach_port_array_t l2l_ports = NULL;
	mach_port_t reqport, rcvright;
	kern_return_t kr = 1;
	launch_data_t out_obj_array = NULL;
	struct ldcred ldc;
	jobmgr_t jmr = NULL;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	runtime_get_caller_creds(&ldc);

	if (target_subset == MACH_PORT_NULL) {
		job_t j2;

		if (j->mgr->session_initialized) {
			if (ldc.uid == 0 && getpid() == 1) {
				if (strcmp(j->mgr->name, VPROCMGR_SESSION_LOGINWINDOW) == 0) {
					job_t ji, jn;

					LIST_FOREACH_SAFE(ji, &j->mgr->jobs, sle, jn) {
						if (!ji->anonymous) {
							job_remove(ji);
						}
					}

					ensure_root_bkgd_setup();

					SLIST_REMOVE(&j->mgr->parentmgr->submgrs, j->mgr, jobmgr_s, sle);
					j->mgr->parentmgr = background_jobmgr;
					SLIST_INSERT_HEAD(&j->mgr->parentmgr->submgrs, j->mgr, sle);

				} else if (strcmp(j->mgr->name, VPROCMGR_SESSION_AQUA) == 0) {
					return 0;
				} else {
					job_log(j, LOG_ERR, "Tried to initialize an already setup session!");
					kr = BOOTSTRAP_NOT_PRIVILEGED;
					goto out;
				}
			} else {
				job_log(j, LOG_ERR, "Tried to initialize an already setup session!");
				kr = BOOTSTRAP_NOT_PRIVILEGED;
				goto out;
			}
		}

		jobmgr_log(j->mgr, LOG_DEBUG, "Renaming to: %s", session_type);
		strcpy(j->mgr->name, session_type);

		if (job_assumes(j, (j2 = jobmgr_init_session(j->mgr, session_type, false)))) {
			job_assumes(j, job_dispatch(j2, true));
		}

		kr = 0;
		goto out;
	} else if (job_mig_intran2(root_jobmgr, target_subset, ldc.pid)) {
		job_log(j, LOG_ERR, "Moving a session to ourself is bogus.");

		kr = BOOTSTRAP_NOT_PRIVILEGED;
		goto out;
	}

	job_log(j, LOG_DEBUG, "Move subset attempt: 0x%x", target_subset);

	kr = _vproc_grab_subset(target_subset, &reqport, &rcvright, &out_obj_array, &l2l_ports, &l2l_port_cnt);

	if (!job_assumes(j, kr == 0)) {
		goto out;
	}

	launchd_assert(launch_data_array_get_count(out_obj_array) == l2l_port_cnt);

	if (!job_assumes(j, (jmr = jobmgr_new(j->mgr, reqport, rcvright, false, session_type)) != NULL)) {
		kr = BOOTSTRAP_NO_MEMORY;
		goto out;
	}

	for (l2l_i = 0; l2l_i < l2l_port_cnt; l2l_i++) {
		launch_data_t tmp, obj_at_idx;
		struct machservice *ms;
		job_t j_for_service;
		const char *serv_name;
		pid_t target_pid;
		bool serv_perpid;

		job_assumes(j, obj_at_idx = launch_data_array_get_index(out_obj_array, l2l_i));
		job_assumes(j, tmp = launch_data_dict_lookup(obj_at_idx, TAKE_SUBSET_PID));
		target_pid = launch_data_get_integer(tmp);
		job_assumes(j, tmp = launch_data_dict_lookup(obj_at_idx, TAKE_SUBSET_PERPID));
		serv_perpid = launch_data_get_bool(tmp);
		job_assumes(j, tmp = launch_data_dict_lookup(obj_at_idx, TAKE_SUBSET_NAME));
		serv_name = launch_data_get_string(tmp);

		j_for_service = jobmgr_find_by_pid(jmr, target_pid, true);

		if (!jobmgr_assumes(jmr, j_for_service != NULL)) {
			kr = BOOTSTRAP_NO_MEMORY;
			goto out;
		}

		if ((ms = machservice_new(j_for_service, serv_name, &l2l_ports[l2l_i], serv_perpid))) {
			machservice_request_notifications(ms);
		}
	}

	kr = 0;

out:
	if (out_obj_array) {
		launch_data_free(out_obj_array);
	}

	if (l2l_ports) {
		mig_deallocate((vm_address_t)l2l_ports, l2l_port_cnt * sizeof(l2l_ports[0]));
	}

	if (kr == 0) {
		if (target_subset) {
			job_assumes(j, launchd_mport_deallocate(target_subset) == KERN_SUCCESS);
		}
	} else if (jmr) {
		jobmgr_shutdown(jmr);
	}

	return kr;
}

kern_return_t
job_mig_take_subset(job_t j, mach_port_t *reqport, mach_port_t *rcvright,
		vm_offset_t *outdata, mach_msg_type_number_t *outdataCnt,
		mach_port_array_t *portsp, unsigned int *ports_cnt)
{
	launch_data_t tmp_obj, tmp_dict, outdata_obj_array = NULL;
	mach_port_array_t ports = NULL;
	unsigned int cnt = 0, cnt2 = 0;
	size_t packed_size;
	struct machservice *ms;
	jobmgr_t jm;
	job_t ji;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	jm = j->mgr;

	if (getpid() != 1) {
		job_log(j, LOG_ERR, "Only the system launchd will transfer Mach sub-bootstraps.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (jobmgr_parent(jm) == NULL) {
		job_log(j, LOG_ERR, "Root Mach bootstrap cannot be transferred.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (strcasecmp(jm->name, VPROCMGR_SESSION_AQUA) == 0) {
		job_log(j, LOG_ERR, "Cannot transfer a setup GUI session.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	} else if (!j->anonymous) {
		job_log(j, LOG_ERR, "Only the anonymous job can transfer Mach sub-bootstraps.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	job_log(j, LOG_DEBUG, "Transferring sub-bootstrap to the per session launchd.");

	outdata_obj_array = launch_data_alloc(LAUNCH_DATA_ARRAY);
	if (!job_assumes(j, outdata_obj_array)) {
		goto out_bad;
	}

	*outdataCnt = 20 * 1024 * 1024;
	mig_allocate(outdata, *outdataCnt);
	if (!job_assumes(j, *outdata != 0)) {
		return 1;
	}

	LIST_FOREACH(ji, &j->mgr->jobs, sle) {
		if (!ji->anonymous) {
			continue;
		}
		SLIST_FOREACH(ms, &ji->machservices, sle) {
			cnt++;
		}
	}

	mig_allocate((vm_address_t *)&ports, cnt * sizeof(ports[0]));
	if (!launchd_assumes(ports != NULL)) {
		goto out_bad;
	}

	LIST_FOREACH(ji, &j->mgr->jobs, sle) {
		if (!ji->anonymous) {
			continue;
		}

		SLIST_FOREACH(ms, &ji->machservices, sle) {
			if (job_assumes(j, (tmp_dict = launch_data_alloc(LAUNCH_DATA_DICTIONARY)))) {
				job_assumes(j, launch_data_array_set_index(outdata_obj_array, tmp_dict, cnt2));
			} else {
				goto out_bad;
			}

			if (job_assumes(j, (tmp_obj = launch_data_new_string(machservice_name(ms))))) {
				job_assumes(j, launch_data_dict_insert(tmp_dict, tmp_obj, TAKE_SUBSET_NAME));
			} else {
				goto out_bad;
			}

			if (job_assumes(j, (tmp_obj = launch_data_new_integer((ms->job->p))))) {
				job_assumes(j, launch_data_dict_insert(tmp_dict, tmp_obj, TAKE_SUBSET_PID));
			} else {
				goto out_bad;
			}

			if (job_assumes(j, (tmp_obj = launch_data_new_bool((ms->per_pid))))) {
				job_assumes(j, launch_data_dict_insert(tmp_dict, tmp_obj, TAKE_SUBSET_PERPID));
			} else {
				goto out_bad;
			}

			ports[cnt2] = machservice_port(ms);

			/* Increment the send right by one so we can shutdown the jobmgr cleanly */
			jobmgr_assumes(jm, (errno = mach_port_mod_refs(mach_task_self(), ports[cnt2], MACH_PORT_RIGHT_SEND, 1)) == 0);
			cnt2++;
		}
	}

	launchd_assumes(cnt == cnt2);

	packed_size = launch_data_pack(outdata_obj_array, (void *)*outdata, *outdataCnt, NULL, NULL);
	if (!job_assumes(j, packed_size != 0)) {
		goto out_bad;
	}

	launch_data_free(outdata_obj_array);

	*portsp = ports;
	*ports_cnt = cnt;

	*reqport = jm->req_port;
	*rcvright = jm->jm_port;

	jm->req_port = 0;
	jm->jm_port = 0;

	jobmgr_shutdown(jm);

	return BOOTSTRAP_SUCCESS;

out_bad:
	if (outdata_obj_array) {
		launch_data_free(outdata_obj_array);
	}
	if (*outdata) {
		mig_deallocate(*outdata, *outdataCnt);
	}
	if (ports) {
		mig_deallocate((vm_address_t)ports, cnt * sizeof(ports[0]));
	}

	return BOOTSTRAP_NO_MEMORY;
}

kern_return_t
job_mig_subset(job_t j, mach_port_t requestorport, mach_port_t *subsetportp)
{
	int bsdepth = 0;
	jobmgr_t jmr;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	jmr = j->mgr;

	while ((jmr = jobmgr_parent(jmr)) != NULL) {
		bsdepth++;
	}

	/* Since we use recursion, we need an artificial depth for subsets */
	if (bsdepth > 100) {
		job_log(j, LOG_ERR, "Mach sub-bootstrap create request failed. Depth greater than: %d", bsdepth);
		return BOOTSTRAP_NO_MEMORY;
	}

	if ((jmr = jobmgr_new(j->mgr, requestorport, MACH_PORT_NULL, false, NULL)) == NULL) {
		if (requestorport == MACH_PORT_NULL) {
			return BOOTSTRAP_NOT_PRIVILEGED;
		}
		return BOOTSTRAP_NO_MEMORY;
	}

	*subsetportp = jmr->jm_port;
	return BOOTSTRAP_SUCCESS;
}

kern_return_t
job_mig_create_service(job_t j, name_t servicename, mach_port_t *serviceportp)
{
	struct machservice *ms;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (job_prog(j)[0] == '\0') {
		job_log(j, LOG_ERR, "Mach service creation requires a target server: %s", servicename);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	if (!j->legacy_mach_job) {
		job_log(j, LOG_ERR, "bootstrap_create_service() is only allowed against legacy Mach jobs: %s", servicename);
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	ms = jobmgr_lookup_service(j->mgr, servicename, false, 0);
	if (ms) {
		job_log(j, LOG_DEBUG, "Mach service creation attempt for failed. Already exists: %s", servicename);
		return BOOTSTRAP_NAME_IN_USE;
	}

	job_checkin(j);

	*serviceportp = MACH_PORT_NULL;
	ms = machservice_new(j, servicename, serviceportp, false);

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
	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}
#if 0
	struct ldcred ldc;
	runtime_get_caller_creds(&ldc);
#endif
	return job_handle_mpm_wait(j, srp, waitstatus);
}

kern_return_t
job_mig_uncork_fork(job_t j)
{
	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (!j->stall_before_exec) {
		job_log(j, LOG_WARNING, "Attempt to uncork a job that isn't in the middle of a fork().");
		return 1;
	}

	job_uncork_fork(j);
	j->stall_before_exec = false;
	return 0;
}

kern_return_t
job_mig_set_service_policy(job_t j, pid_t target_pid, uint64_t flags, name_t target_service)
{
	job_t target_j;

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (!job_assumes(j, (target_j = jobmgr_find_by_pid(j->mgr, target_pid, true)) != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (SLIST_EMPTY(&j->mspolicies)) {
		job_log(j, LOG_DEBUG, "Setting policy on job \"%s\" for Mach service: %s", target_j->label, target_service);
		if (target_service[0]) {
			job_assumes(j, mspolicy_new(target_j, target_service, flags & BOOTSTRAP_ALLOW_LOOKUP, flags & BOOTSTRAP_PER_PID_SERVICE, false));
		} else {
			target_j->deny_unknown_mslookups = !(flags & BOOTSTRAP_ALLOW_LOOKUP);
		}
	} else {
		job_log(j, LOG_WARNING, "Jobs that have policies assigned to them may not set policies.");
		return BOOTSTRAP_NOT_PRIVILEGED;
	}

	return 0;
}

kern_return_t
job_mig_spawn(job_t j, vm_offset_t indata, mach_msg_type_number_t indataCnt, pid_t *child_pid, mach_port_t *obsvr_port)
{
	launch_data_t input_obj = NULL;
	size_t data_offset = 0;
	struct ldcred ldc;
	job_t jr;

	runtime_get_caller_creds(&ldc);

	if (!launchd_assumes(j != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (getpid() == 1 && ldc.euid && ldc.uid) {
		job_log(j, LOG_DEBUG, "Punting spawn to per-user-context");
		return VPROC_ERR_TRY_PER_USER;
	}

	if (indataCnt == 0) {
		return 1;
	}

	if (!job_assumes(j, (input_obj = launch_data_unpack((void *)indata, indataCnt, NULL, 0, &data_offset, NULL)) != NULL)) {
		return 1;
	}

	jr = jobmgr_import2(j->mgr, input_obj);

	if (jr == NULL) switch (errno) {
	case EEXIST:
		return BOOTSTRAP_NAME_IN_USE;
	default:
		return BOOTSTRAP_NO_MEMORY;
	}

	job_reparent_hack(jr, NULL);

	if (getpid() == 1) {
		jr->mach_uid = ldc.uid;
	}

	jr->unload_at_exit = true;
	jr->wait4pipe_eof = true;
	jr->stall_before_exec = jr->wait4debugger;
	jr->wait4debugger = false;

	jr = job_dispatch(jr, true);

	if (!job_assumes(j, jr != NULL)) {
		return BOOTSTRAP_NO_MEMORY;
	}

	if (!job_setup_machport(jr)) {
		job_remove(jr);
		return BOOTSTRAP_NO_MEMORY;
	}

	job_log(j, LOG_INFO, "Spawned");

	*child_pid = job_get_pid(jr);
	*obsvr_port = jr->j_port;

	mig_deallocate(indata, indataCnt);

	return BOOTSTRAP_SUCCESS;
}

void
jobmgr_init(bool sflag)
{
	const char *root_session_type = getpid() == 1 ? VPROCMGR_SESSION_SYSTEM : VPROCMGR_SESSION_BACKGROUND;

	launchd_assert((root_jobmgr = jobmgr_new(NULL, MACH_PORT_NULL, MACH_PORT_NULL, sflag, root_session_type)) != NULL);
}

size_t
our_strhash(const char *s)
{
	size_t c, r = 5381;

	/* djb2
	 * This algorithm was first reported by Dan Bernstein many years ago in comp.lang.c
	 */

	while ((c = *s++)) {
		r = ((r << 5) + r) + c; /* hash*33 + c */
	}

	return r;
}

size_t
hash_label(const char *label)
{
	return our_strhash(label) % LABEL_HASH_SIZE;
}

size_t
hash_ms(const char *msstr)
{
	return our_strhash(msstr) % MACHSERVICE_HASH_SIZE;
}

bool
mspolicy_copy(job_t j_to, job_t j_from)
{
	struct mspolicy *msp;

	SLIST_FOREACH(msp, &j_from->mspolicies, sle) {
		if (!mspolicy_new(j_to, msp->name, msp->allow, msp->per_pid, true)) {
			return false;
		}
	}

	return true;
}

bool
mspolicy_new(job_t j, const char *name, bool allow, bool pid_local, bool skip_check)
{
	struct mspolicy *msp;

	if (!skip_check) SLIST_FOREACH(msp, &j->mspolicies, sle) {
		if (msp->per_pid != pid_local) {
			continue;
		} else if (strcmp(msp->name, name) == 0) {
			return false;
		}
	}

	if ((msp = calloc(1, sizeof(struct mspolicy) + strlen(name) + 1)) == NULL) {
		return false;
	}

	strcpy((char *)msp->name, name);
	msp->per_pid = pid_local;
	msp->allow = allow;

	SLIST_INSERT_HEAD(&j->mspolicies, msp, sle);

	return true;
}

void
mspolicy_setup(launch_data_t obj, const char *key, void *context)
{
	job_t j = context;

	if (launch_data_get_type(obj) != LAUNCH_DATA_BOOL) {
		job_log(j, LOG_WARNING, "Invalid object type for Mach service policy key: %s", key);
		return;
	}

	job_assumes(j, mspolicy_new(j, key, launch_data_get_bool(obj), false, false));
}

bool
mspolicy_check(job_t j, const char *name, bool pid_local)
{
	struct mspolicy *mspi;

	SLIST_FOREACH(mspi, &j->mspolicies, sle) {
		if (mspi->per_pid != pid_local) {
			continue;
		} else if (strcmp(mspi->name, name) != 0) {
			continue;
		}
		return mspi->allow;
	}

	return !j->deny_unknown_mslookups;
}

void
mspolicy_delete(job_t j, struct mspolicy *msp)
{
	SLIST_REMOVE(&j->mspolicies, msp, mspolicy, sle);

	free(msp);
}
