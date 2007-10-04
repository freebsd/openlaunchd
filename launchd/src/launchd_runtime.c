/*
 * Copyright (c) 1999-2006 Apple Computer, Inc. All rights reserved.
 *
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
#include "launchd_runtime.h"

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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/fcntl.h>
#include <bsm/libbsm.h>
#include <malloc/malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <signal.h>
#include <dlfcn.h>

#include "launchd_internalServer.h"
#include "launchd_internal.h"
#include "notifyServer.h"

/* We shouldn't be including these */
#include "launch.h"
#include "launchd.h"
#include "launchd_core_logic.h"
#include "libvproc_internal.h"
#include "job_reply.h"

static mach_port_t ipc_port_set;
static mach_port_t demand_port_set;
static mach_port_t launchd_internal_port;
static int mainkq;

#define BULK_KEV_MAX 100
static struct kevent *bulk_kev;
static int bulk_kev_i;
static int bulk_kev_cnt;

static pthread_t kqueue_demand_thread;
static pthread_t demand_thread;

static void *mport_demand_loop(void *arg);
static void *kqueue_demand_loop(void *arg);
static void log_kevent_struct(int level, struct kevent *kev, int indx);

static void record_caller_creds(mach_msg_header_t *mh);
static void launchd_runtime2(mach_msg_size_t msg_size, mig_reply_error_t *bufRequest, mig_reply_error_t *bufReply);
static mach_msg_size_t max_msg_size;
static mig_callback *mig_cb_table;
static size_t mig_cb_table_sz;
static timeout_callback runtime_idle_callback;
static mach_msg_timeout_t runtime_idle_timeout;
static audit_token_t *au_tok;
static size_t runtime_busy_cnt;


static STAILQ_HEAD(, logmsg_s) logmsg_queue = STAILQ_HEAD_INITIALIZER(logmsg_queue);
static size_t logmsg_queue_sz;
static size_t logmsg_queue_cnt;
static mach_port_t drain_reply_port;
static void runtime_log_uncork_pending_drain(void);
static kern_return_t runtime_log_pack(vm_offset_t *outval, mach_msg_type_number_t *outvalCnt);
static void runtime_log_push(void);

static bool logmsg_add(struct runtime_syslog_attr *attr, int err_num, const char *msg);
static void logmsg_remove(struct logmsg_s *lm);


static const int sigigns[] = { SIGHUP, SIGINT, SIGPIPE, SIGALRM, SIGTERM,
	SIGURG, SIGTSTP, SIGTSTP, SIGCONT, SIGTTIN, SIGTTOU, SIGIO, SIGXCPU,
	SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2
};
static sigset_t sigign_set;

void
launchd_runtime_init(void)
{
	mach_msg_size_t mxmsgsz;
	pthread_attr_t attr;

	launchd_assert((mainkq = kqueue()) != -1);

	launchd_assert((errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &demand_port_set)) == KERN_SUCCESS);
	launchd_assert((errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &ipc_port_set)) == KERN_SUCCESS);

	launchd_assert(launchd_mport_create_recv(&launchd_internal_port) == KERN_SUCCESS);
	launchd_assert(launchd_mport_make_send(launchd_internal_port) == KERN_SUCCESS);

	/* Sigh... at the moment, MIG has maxsize == sizeof(reply union) */
	mxmsgsz = sizeof(union __RequestUnion__x_launchd_internal_subsystem);
	if (x_launchd_internal_subsystem.maxsize > mxmsgsz) {
		mxmsgsz = x_launchd_internal_subsystem.maxsize;
	}

	launchd_assert(runtime_add_mport(launchd_internal_port, launchd_internal_demux, mxmsgsz) == KERN_SUCCESS);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
	launchd_assert(pthread_create(&kqueue_demand_thread, &attr, kqueue_demand_loop, NULL) == 0);
	pthread_attr_destroy(&attr);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
	launchd_assert(pthread_create(&demand_thread, &attr, mport_demand_loop, NULL) == 0);
	pthread_attr_destroy(&attr);
}

void
launchd_runtime_init2(void)
{
	size_t i;

	for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
		sigaddset(&sigign_set, sigigns[i]);
		launchd_assumes(signal(sigigns[i], SIG_IGN) != SIG_ERR);
	}
}

void *
mport_demand_loop(void *arg __attribute__((unused)))
{
	mach_msg_empty_rcv_t dummy;
	kern_return_t kr;

	for (;;) {
		kr = mach_msg(&dummy.header, MACH_RCV_MSG|MACH_RCV_LARGE, 0, 0, demand_port_set, 0, MACH_PORT_NULL);
		if (kr == MACH_RCV_PORT_CHANGED) {
			break;
		} else if (!launchd_assumes(kr == MACH_RCV_TOO_LARGE)) {
			continue;
		}
		launchd_assumes(handle_mport(launchd_internal_port) == 0);
	}

	return NULL;
}

const char *
proc_flags_to_C_names(unsigned int flags)
{
#define MAX_PFLAG_STR "P_ADVLOCK|P_CONTROLT|P_LP64|P_NOCLDSTOP|P_PPWAIT|P_PROFIL|P_SELECT|P_CONTINUED|P_SUGID|P_SYSTEM|P_TIMEOUT|P_TRACED|P_RESV3|P_WEXIT|P_EXEC|P_OWEUPC|P_AFFINITY|P_TRANSLATED|P_RESV5|P_CHECKOPENEVT|P_DEPENDENCY_CAPABLE|P_REBOOT|P_TBE|P_RESV7|P_THCWD|P_RESV9|P_RESV10|P_RESV11|P_NOSHLIB|P_FORCEQUOTA|P_NOCLDWAIT|P_NOREMOTEHANG|0xdeadbeeffeedface"

	static char flags_buf[sizeof(MAX_PFLAG_STR)];
	char *flags_off = NULL;

	if (!flags) {
		return "";
	}

	while (flags) {
		if (flags_off) {
			*flags_off = '|';
			flags_off++;
			*flags_off = '\0';
		} else {
			flags_off = flags_buf;
		}

#define FLAGIF(f) if (flags & f) { flags_off += sprintf(flags_off, #f); flags &= ~f; }

		FLAGIF(P_ADVLOCK)
		else FLAGIF(P_CONTROLT)
		else FLAGIF(P_LP64)
		else FLAGIF(P_NOCLDSTOP)
		else FLAGIF(P_PPWAIT)
		else FLAGIF(P_PROFIL)
		else FLAGIF(P_SELECT)
		else FLAGIF(P_CONTINUED)
		else FLAGIF(P_SUGID)
		else FLAGIF(P_SYSTEM)
		else FLAGIF(P_TIMEOUT)
		else FLAGIF(P_TRACED)
		else FLAGIF(P_RESV3)
		else FLAGIF(P_WEXIT)
		else FLAGIF(P_EXEC)
		else FLAGIF(P_OWEUPC)
		else FLAGIF(P_AFFINITY)
		else FLAGIF(P_TRANSLATED)
		else FLAGIF(P_RESV5)
		else FLAGIF(P_CHECKOPENEVT)
		else FLAGIF(P_DEPENDENCY_CAPABLE)
		else FLAGIF(P_REBOOT)
		else FLAGIF(P_TBE)
		else FLAGIF(P_RESV7)
		else FLAGIF(P_THCWD)
		else FLAGIF(P_RESV9)
		else FLAGIF(P_RESV10)
		else FLAGIF(P_RESV11)
		else FLAGIF(P_NOSHLIB)
		else FLAGIF(P_FORCEQUOTA)
		else FLAGIF(P_NOCLDWAIT)
		else FLAGIF(P_NOREMOTEHANG)
		else {
			flags_off += sprintf(flags_off, "0x%x", flags);
			flags = 0;
		}
	}

	return flags_buf;
}

const char *
reboot_flags_to_C_names(unsigned int flags)
{
#define MAX_RB_STR "RB_ASKNAME|RB_SINGLE|RB_NOSYNC|RB_KDB|RB_HALT|RB_INITNAME|RB_DFLTROOT|RB_ALTBOOT|RB_UNIPROC|RB_SAFEBOOT|RB_UPSDELAY|0xdeadbeeffeedface"
	static char flags_buf[sizeof(MAX_RB_STR)];
	char *flags_off = NULL;

	if (flags) while (flags) {
		if (flags_off) {
			*flags_off = '|';
			flags_off++;
			*flags_off = '\0';
		} else {
			flags_off = flags_buf;
		}

		FLAGIF(RB_ASKNAME)
		else FLAGIF(RB_SINGLE)
		else FLAGIF(RB_NOSYNC)
		else FLAGIF(RB_KDB)
		else FLAGIF(RB_HALT)
		else FLAGIF(RB_INITNAME)
		else FLAGIF(RB_DFLTROOT)
		else FLAGIF(RB_ALTBOOT)
		else FLAGIF(RB_UNIPROC)
		else FLAGIF(RB_SAFEBOOT)
		else FLAGIF(RB_UPSDELAY)
		else {
			flags_off += sprintf(flags_off, "0x%x", flags);
			flags = 0;
		}
		return flags_buf;
	} else {
		return "RB_AUTOBOOT";
	}
}

const char *
signal_to_C_name(unsigned int sig)
{
	static char unknown[25];

#define SIG2CASE(sg)	case sg: return #sg

	switch (sig) {
	SIG2CASE(SIGHUP);
	SIG2CASE(SIGINT);
	SIG2CASE(SIGQUIT);
	SIG2CASE(SIGILL);
	SIG2CASE(SIGTRAP);
	SIG2CASE(SIGABRT);
	SIG2CASE(SIGFPE);
	SIG2CASE(SIGKILL);
	SIG2CASE(SIGBUS);
	SIG2CASE(SIGSEGV);
	SIG2CASE(SIGSYS);
	SIG2CASE(SIGPIPE);
	SIG2CASE(SIGALRM);
	SIG2CASE(SIGTERM);
	SIG2CASE(SIGURG);
	SIG2CASE(SIGSTOP);
	SIG2CASE(SIGTSTP);
	SIG2CASE(SIGCONT);
	SIG2CASE(SIGCHLD);
	SIG2CASE(SIGTTIN);
	SIG2CASE(SIGTTOU);
	SIG2CASE(SIGIO);
	SIG2CASE(SIGXCPU);
	SIG2CASE(SIGXFSZ);
	SIG2CASE(SIGVTALRM);
	SIG2CASE(SIGPROF);
	SIG2CASE(SIGWINCH);
	SIG2CASE(SIGINFO);
	SIG2CASE(SIGUSR1);
	SIG2CASE(SIGUSR2);
	default:
		snprintf(unknown, sizeof(unknown), "%u", sig);
		return unknown;
	}
}

void
log_kevent_struct(int level, struct kevent *kev, int indx)
{
	const char *filter_str;
	char ident_buf[100];
	char filter_buf[100];
	char fflags_buf[1000];
	char flags_buf[1000] = "0x0";
	char *flags_off = NULL;
	char *fflags_off = NULL;
	unsigned short flags = kev->flags;
	unsigned int fflags = kev->fflags;

	if (flags) while (flags) {
		if (flags_off) {
			*flags_off = '|';
			flags_off++;
			*flags_off = '\0';
		} else {
			flags_off = flags_buf;
		}

		FLAGIF(EV_ADD)
		else FLAGIF(EV_RECEIPT)
		else FLAGIF(EV_DELETE)
		else FLAGIF(EV_ENABLE)
		else FLAGIF(EV_DISABLE)
		else FLAGIF(EV_CLEAR)
		else FLAGIF(EV_EOF)
		else FLAGIF(EV_ONESHOT)
		else FLAGIF(EV_ERROR)
		else {
			flags_off += sprintf(flags_off, "0x%x", flags);
			flags = 0;
		}
	}

	snprintf(ident_buf, sizeof(ident_buf), "%ld", kev->ident);
	snprintf(fflags_buf, sizeof(fflags_buf), "0x%x", fflags);

	switch (kev->filter) {
	case EVFILT_READ:
		filter_str = "EVFILT_READ";
		break;
	case EVFILT_WRITE:
		filter_str = "EVFILT_WRITE";
		break;
	case EVFILT_AIO:
		filter_str = "EVFILT_AIO";
		break;
	case EVFILT_VNODE:
		filter_str = "EVFILT_VNODE";
		if (fflags) while (fflags) {
			if (fflags_off) {
				*fflags_off = '|';
				fflags_off++;
				*fflags_off = '\0';
			} else {
				fflags_off = fflags_buf;
			}

#define FFLAGIF(ff) if (fflags & ff) { fflags_off += sprintf(fflags_off, #ff); fflags &= ~ff; }

			FFLAGIF(NOTE_DELETE)
			else FFLAGIF(NOTE_WRITE)
			else FFLAGIF(NOTE_EXTEND)
			else FFLAGIF(NOTE_ATTRIB)
			else FFLAGIF(NOTE_LINK)
			else FFLAGIF(NOTE_RENAME)
			else FFLAGIF(NOTE_REVOKE)
			else {
				fflags_off += sprintf(fflags_off, "0x%x", fflags);
				fflags = 0;
			}
		}
		break;
	case EVFILT_PROC:
		filter_str = "EVFILT_PROC";
		if (fflags) while (fflags) {
			if (fflags_off) {
				*fflags_off = '|';
				fflags_off++;
				*fflags_off = '\0';
			} else {
				fflags_off = fflags_buf;
			}

			FFLAGIF(NOTE_EXIT)
			else FFLAGIF(NOTE_REAP)
			else FFLAGIF(NOTE_FORK)
			else FFLAGIF(NOTE_EXEC)
			else FFLAGIF(NOTE_SIGNAL)
			else FFLAGIF(NOTE_TRACK)
			else FFLAGIF(NOTE_TRACKERR)
			else FFLAGIF(NOTE_CHILD)
			else {
				fflags_off += sprintf(fflags_off, "0x%x", fflags);
				fflags = 0;
			}
		}
		break;
	case EVFILT_SIGNAL:
		filter_str = "EVFILT_SIGNAL";
		strcpy(ident_buf, signal_to_C_name(kev->ident));
		break;
	case EVFILT_TIMER:
		filter_str = "EVFILT_TIMER";
		snprintf(ident_buf, sizeof(ident_buf), "0x%lx", kev->ident);
		if (fflags) while (fflags) {
			if (fflags_off) {
				*fflags_off = '|';
				fflags_off++;
				*fflags_off = '\0';
			} else {
				fflags_off = fflags_buf;
			}

			FFLAGIF(NOTE_SECONDS)
			else FFLAGIF(NOTE_USECONDS)
			else FFLAGIF(NOTE_NSECONDS)
			else FFLAGIF(NOTE_ABSOLUTE)
			else {
				fflags_off += sprintf(fflags_off, "0x%x", fflags);
				fflags = 0;
			}
		}
		break;
	case EVFILT_MACHPORT:
		filter_str = "EVFILT_MACHPORT";
		snprintf(ident_buf, sizeof(ident_buf), "0x%lx", kev->ident);
		break;
	case EVFILT_FS:
		filter_str = "EVFILT_FS";
		snprintf(ident_buf, sizeof(ident_buf), "0x%lx", kev->ident);
		if (fflags) while (fflags) {
			if (fflags_off) {
				*fflags_off = '|';
				fflags_off++;
				*fflags_off = '\0';
			} else {
				fflags_off = fflags_buf;
			}

			FFLAGIF(VQ_NOTRESP)
			else FFLAGIF(VQ_NEEDAUTH)
			else FFLAGIF(VQ_LOWDISK)
			else FFLAGIF(VQ_MOUNT)
			else FFLAGIF(VQ_UNMOUNT)
			else FFLAGIF(VQ_DEAD)
			else FFLAGIF(VQ_ASSIST)
			else FFLAGIF(VQ_NOTRESPLOCK)
			else FFLAGIF(VQ_UPDATE)
			else {
				fflags_off += sprintf(fflags_off, "0x%x", fflags);
				fflags = 0;
			}
		}
		break;
	default:
		snprintf(filter_buf, sizeof(filter_buf), "%d", kev->filter);
		filter_str = filter_buf;
		break;
	}

	runtime_syslog(level, "KEVENT[%d]: udata = %p data = 0x%lx ident = %s filter = %s flags = %s fflags = %s",
			indx, kev->udata, kev->data, ident_buf, filter_str, flags_buf, fflags_buf);
}

kern_return_t
x_handle_mport(mach_port_t junk __attribute__((unused)))
{
	mach_port_name_array_t members;
	mach_msg_type_number_t membersCnt;
	mach_port_status_t status;
	mach_msg_type_number_t statusCnt;
	struct kevent kev;
	unsigned int i;

	if (!launchd_assumes((errno = mach_port_get_set_status(mach_task_self(), demand_port_set, &members, &membersCnt)) == KERN_SUCCESS)) {
		return 1;
	}

	for (i = 0; i < membersCnt; i++) {
		statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
		if (mach_port_get_attributes(mach_task_self(), members[i], MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status,
					&statusCnt) != KERN_SUCCESS) {
			continue;
		}
		if (status.mps_msgcount) {
			EV_SET(&kev, members[i], EVFILT_MACHPORT, 0, 0, 0, job_find_by_service_port(members[i]));
#if 0
			if (launchd_assumes(kev.udata != NULL)) {
#endif
				log_kevent_struct(LOG_DEBUG, &kev, 0);
				(*((kq_callback *)kev.udata))(kev.udata, &kev);
#if 0
			} else {
				log_kevent_struct(LOG_ERR, &kev);
			}
#endif
			/* the callback may have tainted our ability to continue this for loop */
			break;
		}
	}

	launchd_assumes(vm_deallocate(mach_task_self(), (vm_address_t)members,
				(vm_size_t) membersCnt * sizeof(mach_port_name_t)) == KERN_SUCCESS);

	return 0;
}

void *
kqueue_demand_loop(void *arg __attribute__((unused)))
{
	fd_set rfds;

	/*
	 * Yes, at first glance, calling select() on a kqueue seems silly.
	 *
	 * This avoids a race condition between the main thread and this helper
	 * thread by ensuring that we drain kqueue events on the same thread
	 * that manipulates the kqueue.
	 */

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(mainkq, &rfds);
		if (launchd_assumes(select(mainkq + 1, &rfds, NULL, NULL, NULL) == 1)) {
			launchd_assumes(handle_kqueue(launchd_internal_port, mainkq) == 0);
		}
	}

	return NULL;
}

kern_return_t
x_handle_kqueue(mach_port_t junk __attribute__((unused)), integer_t fd)
{
	struct timespec ts = { 0, 0 };
	struct kevent kev[BULK_KEV_MAX];
	int i;

	bulk_kev = kev;

	launchd_assumes((bulk_kev_cnt = kevent(fd, NULL, 0, kev, BULK_KEV_MAX, &ts)) != -1);

	if (bulk_kev_cnt > 0) {
#if 0
		Dl_info dli;

		if (launchd_assumes(malloc_size(kev.udata) || dladdr(kev.udata, &dli))) {
#endif
		for (i = 0; i < bulk_kev_cnt; i++) {
			log_kevent_struct(LOG_DEBUG, &kev[i], i);
		}
		for (i = 0; i < bulk_kev_cnt; i++) {
			bulk_kev_i = i;
			if (kev[i].filter) {
				(*((kq_callback *)kev[i].udata))(kev[i].udata, &kev[i]);
			}
		}
#if 0
		} else {
			log_kevent_struct(LOG_ERR, &kev);
		}
#endif
	}

	bulk_kev = NULL;

	return 0;
}



void
launchd_runtime(void)
{
	mig_reply_error_t *req = NULL, *resp = NULL;
	mach_msg_size_t mz = max_msg_size;
	int flags = VM_MAKE_TAG(VM_MEMORY_MACH_MSG)|TRUE;

	for (;;) {
		if (req) {
			launchd_assumes(vm_deallocate(mach_task_self(), (vm_address_t)req, mz) == KERN_SUCCESS);
			req = NULL;
		}
		if (resp) {
			launchd_assumes(vm_deallocate(mach_task_self(), (vm_address_t)resp, mz) == KERN_SUCCESS);
			resp = NULL;
		}

		mz = max_msg_size;

		if (!launchd_assumes(vm_allocate(mach_task_self(), (vm_address_t *)&req, mz, flags) == KERN_SUCCESS)) {
			continue;
		}
		if (!launchd_assumes(vm_allocate(mach_task_self(), (vm_address_t *)&resp, mz, flags) == KERN_SUCCESS)) {
			continue;
		}

		launchd_runtime2(mz, req, resp);

		/* If we get here, max_msg_size probably changed... */
	}
}

kern_return_t
launchd_set_bport(mach_port_t name)
{
	return errno = task_set_bootstrap_port(mach_task_self(), name);
}

kern_return_t
launchd_get_bport(mach_port_t *name)
{
	return errno = task_get_bootstrap_port(mach_task_self(), name);
}

kern_return_t
launchd_mport_notify_req(mach_port_t name, mach_msg_id_t which)
{
	mach_port_mscount_t msgc = (which == MACH_NOTIFY_PORT_DESTROYED) ? 0 : 1;
	mach_port_t previous, where = (which == MACH_NOTIFY_NO_SENDERS) ? name : launchd_internal_port;

	if (which == MACH_NOTIFY_NO_SENDERS) {
		/* Always make sure the send count is zero, in case a receive right is reused */
		errno = mach_port_set_mscount(mach_task_self(), name, 0);
		if (errno != KERN_SUCCESS) {
			return errno;
		}
	}

	errno = mach_port_request_notification(mach_task_self(), name, which, msgc, where,
			MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);

	if (errno == 0 && previous != MACH_PORT_NULL) {
		launchd_assumes(launchd_mport_deallocate(previous) == KERN_SUCCESS);
	}

	return errno;
}

pid_t
runtime_fork(mach_port_t bsport)
{
	sigset_t emptyset, oset;
	pid_t r = -1;
	int saved_errno;
	size_t i;

	sigemptyset(&emptyset);

	launchd_assumes(launchd_mport_make_send(bsport) == KERN_SUCCESS);
	launchd_assumes(launchd_set_bport(bsport) == KERN_SUCCESS);
	launchd_assumes(launchd_mport_deallocate(bsport) == KERN_SUCCESS);

	launchd_assumes(sigprocmask(SIG_BLOCK, &sigign_set, &oset) != -1);
	for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
		launchd_assumes(signal(sigigns[i], SIG_DFL) != SIG_ERR);
	}

	r = fork();
	saved_errno = errno;

	if (r != 0) {
		for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
			launchd_assumes(signal(sigigns[i], SIG_IGN) != SIG_ERR);
		}
		launchd_assumes(sigprocmask(SIG_SETMASK, &oset, NULL) != -1);
		launchd_assumes(launchd_set_bport(MACH_PORT_NULL) == KERN_SUCCESS);
	} else {
		launchd_assumes(sigprocmask(SIG_SETMASK, &emptyset, NULL) != -1);
	}

	errno = saved_errno;

	return r;
}


void
runtime_set_timeout(timeout_callback to_cb, unsigned int sec)
{
	if (sec == 0 || to_cb == NULL) {
		runtime_idle_callback = NULL;
		runtime_idle_timeout = 0;
	}

	runtime_idle_callback = to_cb;
	runtime_idle_timeout = sec * 1000;
}

kern_return_t
runtime_add_mport(mach_port_t name, mig_callback demux, mach_msg_size_t msg_size)
{
	size_t needed_table_sz = (MACH_PORT_INDEX(name) + 1) * sizeof(mig_callback);
	mach_port_t target_set = demux ? ipc_port_set : demand_port_set;

	msg_size = round_page(msg_size + MAX_TRAILER_SIZE);

	if (needed_table_sz > mig_cb_table_sz) {
		needed_table_sz *= 2; /* Let's try and avoid realloc'ing for a while */
		mig_callback *new_table = malloc(needed_table_sz);

		if (!launchd_assumes(new_table != NULL)) {
			return KERN_RESOURCE_SHORTAGE;
		}

		if (mig_cb_table) {
			memcpy(new_table, mig_cb_table, mig_cb_table_sz);
			free(mig_cb_table);
		}

		mig_cb_table_sz = needed_table_sz;
		mig_cb_table = new_table;
	}

	mig_cb_table[MACH_PORT_INDEX(name)] = demux;

	if (msg_size > max_msg_size) {
		max_msg_size = msg_size;
	}

	return errno = mach_port_move_member(mach_task_self(), name, target_set);
}

kern_return_t
runtime_remove_mport(mach_port_t name)
{
	mig_cb_table[MACH_PORT_INDEX(name)] = NULL;

	return errno = mach_port_move_member(mach_task_self(), name, MACH_PORT_NULL);
}

kern_return_t
launchd_mport_make_send(mach_port_t name)
{
	return errno = mach_port_insert_right(mach_task_self(), name, name, MACH_MSG_TYPE_MAKE_SEND);
}

kern_return_t
launchd_mport_close_recv(mach_port_t name)
{
	return errno = mach_port_mod_refs(mach_task_self(), name, MACH_PORT_RIGHT_RECEIVE, -1);
}

kern_return_t
launchd_mport_create_recv(mach_port_t *name)
{
	return errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, name);
}

kern_return_t
launchd_mport_deallocate(mach_port_t name)
{
	return errno = mach_port_deallocate(mach_task_self(), name);
}

int
kevent_bulk_mod(struct kevent *kev, size_t kev_cnt)
{
	size_t i;

	for (i = 0; i < kev_cnt; i++) {
		kev[i].flags |= EV_CLEAR|EV_RECEIPT;
	}

	return kevent(mainkq, kev, kev_cnt, kev, kev_cnt, NULL);
}

int
kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	int r;

	switch (filter) {
	case EVFILT_READ:
	case EVFILT_WRITE:
		break;
	default:
		flags |= EV_CLEAR;
		break;
	}

	flags |= EV_RECEIPT;

	if (flags & EV_ADD && !launchd_assumes(udata != NULL)) {
		errno = EINVAL;
		return -1;
	}

	EV_SET(&kev, ident, filter, flags, fflags, data, udata);

	r = kevent(mainkq, &kev, 1, &kev, 1, NULL);

	if (!launchd_assumes(r == 1)) {
		return -1;
	}

	if (launchd_assumes(kev.flags & EV_ERROR)) {
		if ((flags & EV_ADD) && kev.data) {
			runtime_syslog(LOG_DEBUG, "%s(): See the next line...", __func__);
			log_kevent_struct(LOG_DEBUG, &kev, 0);
			errno = kev.data;
			return -1;
		}
	}

	return r;
}

boolean_t
launchd_internal_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply)
{
	if (launchd_internal_server_routine(Request)) {
		return launchd_internal_server(Request, Reply);
	}

	return notify_server(Request, Reply);
}

kern_return_t
do_mach_notify_port_destroyed(mach_port_t notify, mach_port_t rights)
{
	/* This message is sent to us when a receive right is returned to us. */

	if (!launchd_assumes(job_ack_port_destruction(rights))) {
		launchd_assumes(launchd_mport_close_recv(rights) == KERN_SUCCESS);
	}

	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_port_deleted(mach_port_t notify, mach_port_name_t name)
{
	/* If we deallocate/destroy/mod_ref away a port with a pending
	 * notification, the original notification message is replaced with
	 * this message. To quote a Mach kernel expert, "the kernel has a
	 * send-once right that has to be used somehow."
	 */
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_no_senders(mach_port_t notify, mach_port_mscount_t mscount)
{
	job_t j = job_mig_intran(notify);

	/* This message is sent to us when the last customer of one of our
	 * objects goes away.
	 */

	if (!launchd_assumes(j != NULL)) {
		return KERN_FAILURE;
	}

	job_ack_no_senders(j);

	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_send_once(mach_port_t notify)
{
	/* This message is sent to us every time we close a port that we have
	 * outstanding Mach notification requests on. We can safely ignore this
	 * message.
	 */

	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_dead_name(mach_port_t notify, mach_port_name_t name)
{
	/* This message is sent to us when one of our send rights no longer has
	 * a receiver somewhere else on the system.
	 */

	if (name == drain_reply_port) {
		launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);
		drain_reply_port = MACH_PORT_NULL;
	}

	if (launchd_assumes(root_jobmgr != NULL)) {
		root_jobmgr = jobmgr_delete_anything_with_port(root_jobmgr, name);
	}

	/* A dead-name notification about a port appears to increment the
	 * rights on said port. Let's deallocate it so that we don't leak
	 * dead-name ports.
	 */
	launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);

	return KERN_SUCCESS;
}

void
record_caller_creds(mach_msg_header_t *mh)
{
	mach_msg_max_trailer_t *tp;
	size_t trailer_size;

	tp = (mach_msg_max_trailer_t *)((vm_offset_t)mh + round_msg(mh->msgh_size));

	trailer_size = tp->msgh_trailer_size - (mach_msg_size_t)(sizeof(mach_msg_trailer_type_t) - sizeof(mach_msg_trailer_size_t));

	if (trailer_size < (mach_msg_size_t)sizeof(audit_token_t)) {
		au_tok = NULL;
		return;
	}

	au_tok = &tp->msgh_audit;
}

bool
runtime_get_caller_creds(struct ldcred *ldc)
{
	if (!au_tok) {
		return false;
	}

	audit_token_to_au32(*au_tok, /* audit UID */ NULL, &ldc->euid,
			&ldc->egid, &ldc->uid, &ldc->gid, &ldc->pid,
			&ldc->asid, /* au_tid_t */ NULL);

	return true;
}

void
launchd_runtime2(mach_msg_size_t msg_size, mig_reply_error_t *bufRequest, mig_reply_error_t *bufReply)
{
	mach_msg_options_t options, tmp_options;
	mig_reply_error_t *bufTemp;
	mig_callback the_demux;
	mach_msg_timeout_t to;
	mach_msg_return_t mr;

	options = MACH_RCV_MSG|MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT) |
		MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0);

	tmp_options = options;

	for (;;) {
		to = MACH_MSG_TIMEOUT_NONE;

		if (msg_size != max_msg_size) {
			/* The buffer isn't big enougth to receive messages anymore... */
			tmp_options &= ~MACH_RCV_MSG;
			options &= ~MACH_RCV_MSG;
			if (!(tmp_options & MACH_SEND_MSG)) {
				return;
			}
		}

		if ((tmp_options & MACH_RCV_MSG) && (runtime_idle_callback || (runtime_busy_cnt == 0))) {
			tmp_options |= MACH_RCV_TIMEOUT;

			if (!(tmp_options & MACH_SEND_TIMEOUT)) {
				to = runtime_busy_cnt ? runtime_idle_timeout : (RUNTIME_ADVISABLE_IDLE_TIMEOUT * 1000);
			}
		}

		runtime_log_push();

		mr = mach_msg(&bufReply->Head, tmp_options, bufReply->Head.msgh_size,
				msg_size, ipc_port_set, to, MACH_PORT_NULL);

		tmp_options = options;

		if (mr == MACH_SEND_INVALID_DEST || mr == MACH_SEND_TIMED_OUT) {
			/* We need to clean up and start over. */
			if (bufReply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
				mach_msg_destroy(&bufReply->Head);
			}
			continue;
		} else if (mr == MACH_RCV_TIMED_OUT) {
			if (to != MACH_MSG_TIMEOUT_NONE) {
				if (runtime_busy_cnt == 0) {
					launchd_shutdown();
				} else if (runtime_idle_callback) {
					runtime_idle_callback();
				}
			}
			continue;
		} else if (!launchd_assumes(mr == MACH_MSG_SUCCESS)) {
			continue;
		}

		bufTemp = bufRequest;
		bufRequest = bufReply;
		bufReply = bufTemp;

		if (!(tmp_options & MACH_RCV_MSG)) {
			continue;
		}

		/* we have another request message */

		if (!launchd_assumes(mig_cb_table != NULL)) {
			break;
		}

		the_demux = mig_cb_table[MACH_PORT_INDEX(bufRequest->Head.msgh_local_port)];

		if (!launchd_assumes(the_demux != NULL)) {
			break;
		}

		record_caller_creds(&bufRequest->Head);

		/*
		 * This is a total hack. We really need a bit in the kernel's proc
		 * struct to declare our intent.
		 */
		static int no_hang_fd = -1;
		if (no_hang_fd == -1) {
			no_hang_fd = _fd(open("/dev/autofs_nowait", 0));
		}

		if (the_demux(&bufRequest->Head, &bufReply->Head) == FALSE) {
			/* XXX - also gross */
			if (bufRequest->Head.msgh_id == MACH_NOTIFY_NO_SENDERS) {
				notify_server(&bufRequest->Head, &bufReply->Head);
			}
		}

		if (!(bufReply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
			if (bufReply->RetCode == MIG_NO_REPLY) {
				bufReply->Head.msgh_remote_port = MACH_PORT_NULL;
			} else if ((bufReply->RetCode != KERN_SUCCESS) && (bufRequest->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
				/* destroy the request - but not the reply port */
				bufRequest->Head.msgh_remote_port = MACH_PORT_NULL;
				mach_msg_destroy(&bufRequest->Head);
			}
		}

		if (bufReply->Head.msgh_remote_port != MACH_PORT_NULL) {
			tmp_options |= MACH_SEND_MSG;

			if (MACH_MSGH_BITS_REMOTE(bufReply->Head.msgh_bits) != MACH_MSG_TYPE_MOVE_SEND_ONCE) {
				tmp_options |= MACH_SEND_TIMEOUT;
			}
		}
	}
}

int
runtime_close(int fd)
{
	int i;

	if (bulk_kev) for (i = bulk_kev_i + 1; i < bulk_kev_cnt; i++) {
		switch (bulk_kev[i].filter) {
		case EVFILT_VNODE:
		case EVFILT_WRITE:
		case EVFILT_READ:
			if ((int)bulk_kev[i].ident == fd) {
				runtime_syslog(LOG_DEBUG, "Skipping kevent index: %d", i);
				bulk_kev[i].filter = 0;
			}
		default:
			break;
		}
	}

	return close(fd);
}

static FILE *ourlogfile;

void
runtime_closelog(void)
{
	if (ourlogfile) {
		launchd_assumes(fflush(ourlogfile) == 0);
		launchd_assumes(runtime_fsync(fileno(ourlogfile)) != -1);
	}
}

int
runtime_fsync(int fd)
{
	if (debug_shutdown_hangs) {
		return fcntl(fd, F_FULLFSYNC, NULL);
	} else {
		return fsync(fd);
	}
}

static int internal_mask_pri = LOG_UPTO(LOG_NOTICE);
//static int internal_mask_pri = LOG_UPTO(LOG_DEBUG);

int
runtime_setlogmask(int maskpri)
{
	internal_mask_pri = maskpri;

	return internal_mask_pri;
}

void
runtime_syslog(int pri, const char *message, ...)
{
	struct runtime_syslog_attr attr = {
		"com.apple.launchd", "com.apple.launchd",
		getpid() == 1 ? "System" : "Background",
		pri, getuid(), getpid(), getpid()
	};
	va_list ap;

	va_start(ap, message);

	runtime_vsyslog(&attr, message, ap);

	va_end(ap);
}

void
runtime_vsyslog(struct runtime_syslog_attr *attr, const char *message, va_list args)
{
	static pthread_mutex_t ourlock = PTHREAD_MUTEX_INITIALIZER;
	static struct timeval shutdown_start;
	static struct timeval prev_msg;
	static int apple_internal_logging = 1;
	struct timeval tvnow, tvd_total, tvd_msg_delta = { 0, 0 };
	struct stat sb;
	int saved_errno = errno;
	char newmsg[10000];
	size_t i, j;

	if (!(LOG_MASK(attr->priority) & internal_mask_pri)) {
		goto out;
	}

	if (apple_internal_logging == 1) {
		apple_internal_logging = stat("/AppleInternal", &sb);
	}


	if (!(debug_shutdown_hangs && getpid() == 1)) {
		if (attr->priority == LOG_APPLEONLY) {
			if (apple_internal_logging == -1) {
				goto out;
			}
			attr->priority = LOG_NOTICE;
		}
		vsnprintf(newmsg, sizeof(newmsg), message, args);
		logmsg_add(attr, saved_errno, newmsg);
		goto out;
	}

	if (shutdown_start.tv_sec == 0) {
		gettimeofday(&shutdown_start, NULL);
	}

	if (gettimeofday(&tvnow, NULL) == -1) {
		tvnow.tv_sec = 0;
		tvnow.tv_usec = 0;
	}

	pthread_mutex_lock(&ourlock);

	if (ourlogfile == NULL) {
		rename("/var/log/launchd-shutdown.log", "/var/log/launchd-shutdown.log.1");
		ourlogfile = fopen("/var/log/launchd-shutdown.log", "a");
	}

	pthread_mutex_unlock(&ourlock);

	if (ourlogfile == NULL) {
		goto out;
	}

	if (message == NULL) {
		goto out;
	}

	timersub(&tvnow, &shutdown_start, &tvd_total);

	if (prev_msg.tv_sec != 0) {
		timersub(&tvnow, &prev_msg, &tvd_msg_delta);
	}

	prev_msg = tvnow;

	snprintf(newmsg, sizeof(newmsg), "%3ld.%06d%4ld.%06d%6u %-40s%6u %-40s ",
			tvd_total.tv_sec, tvd_total.tv_usec,
			tvd_msg_delta.tv_sec, tvd_msg_delta.tv_usec,
			attr->from_pid, attr->from_name,
			attr->about_pid, attr->about_name);

	for (i = 0, j = strlen(newmsg); message[i];) {
		if (message[i] == '%' && message[i + 1] == 'm') {
			char *errs = strerror(saved_errno);
			strcpy(newmsg + j, errs ? errs : "unknown error");
			j += strlen(newmsg + j);
			i += 2;
		} else {
			newmsg[j] = message[i];
			j++;
			i++;
		}
	}

	strcpy(newmsg + j, "\n");

	vfprintf(ourlogfile, newmsg, args);

out:
	runtime_log_uncork_pending_drain();
}

bool
logmsg_add(struct runtime_syslog_attr *attr, int err_num, const char *msg)
{
	size_t lm_sz = sizeof(struct logmsg_s) + strlen(msg) + strlen(attr->from_name) + strlen(attr->about_name) + strlen(attr->session_name) + 4;
	char *data_off;
	struct logmsg_s *lm;

#define ROUND_TO_64BIT_WORD_SIZE(x)	((x + 7) & ~7)

	/* we do this to make the unpacking for the log_drain cause unalignment faults */
	lm_sz = ROUND_TO_64BIT_WORD_SIZE(lm_sz);

	if (!(lm = calloc(1, lm_sz))) {
		return false;
	}

	data_off = lm->data;

	launchd_assumes(gettimeofday(&lm->when, NULL) != -1);
	lm->from_pid = attr->from_pid;
	lm->about_pid = attr->about_pid;
	lm->err_num = err_num;
	lm->pri = attr->priority;
	lm->obj_sz = lm_sz;
	lm->msg = data_off;
	data_off += sprintf(data_off, "%s", msg) + 1;
	lm->from_name = data_off;
	data_off += sprintf(data_off, "%s", attr->from_name) + 1;
	lm->about_name = data_off;
	data_off += sprintf(data_off, "%s", attr->about_name) + 1;
	lm->session_name = data_off;
	data_off += sprintf(data_off, "%s", attr->session_name) + 1;

	STAILQ_INSERT_TAIL(&logmsg_queue, lm, sqe);
	logmsg_queue_sz += lm_sz;
	logmsg_queue_cnt++;

	return true;
}

void
logmsg_remove(struct logmsg_s *lm)
{
	STAILQ_REMOVE(&logmsg_queue, lm, logmsg_s, sqe);
	logmsg_queue_sz -= lm->obj_sz;
	logmsg_queue_cnt--;

	free(lm);
}
 
kern_return_t
runtime_log_pack(vm_offset_t *outval, mach_msg_type_number_t *outvalCnt)
{
	struct logmsg_s *lm;
	void *offset;

	*outvalCnt = logmsg_queue_sz;

	mig_allocate(outval, *outvalCnt);

	if (*outval == 0) {
		return 1;
	}

	offset = (void *)*outval;

	while ((lm = STAILQ_FIRST(&logmsg_queue))) {
		lm->from_name -= (size_t)lm;
		lm->about_name -= (size_t)lm;
		lm->msg -= (size_t)lm;
		lm->session_name -= (size_t)lm;

		memcpy(offset, lm, lm->obj_sz);
		
		offset += lm->obj_sz;

		logmsg_remove(lm);
	}

	return 0;
}

void
runtime_log_uncork_pending_drain(void)
{
	mach_msg_type_number_t outvalCnt;
	mach_port_t tmp_port;
	vm_offset_t outval;

	if (!drain_reply_port) {
		return;
	}

	if (logmsg_queue_cnt == 0) {
		return;
	}

	if (runtime_log_pack(&outval, &outvalCnt) != 0) {
		return;
	}

	tmp_port = drain_reply_port;
	drain_reply_port = MACH_PORT_NULL;

	if ((errno = job_mig_log_drain_reply(tmp_port, 0, outval, outvalCnt))) {
		launchd_assumes(errno == MACH_SEND_INVALID_DEST);
		launchd_assumes(launchd_mport_deallocate(tmp_port) == KERN_SUCCESS);
	}

	mig_deallocate(outval, outvalCnt);
}

void
runtime_log_push(void)
{
	mach_msg_type_number_t outvalCnt;
	vm_offset_t outval;

	if (logmsg_queue_cnt == 0) {
		launchd_assumes(STAILQ_EMPTY(&logmsg_queue));
		return;
	} else if (getpid() == 1) {
		return;
	}

	if (runtime_log_pack(&outval, &outvalCnt) != 0) {
		return;
	}

	launchd_assumes(_vprocmgr_log_forward(inherited_bootstrap_port, (void *)outval, outvalCnt) == NULL);

	mig_deallocate(outval, outvalCnt);
}

kern_return_t
runtime_log_forward(uid_t forward_uid, gid_t forward_gid, vm_offset_t inval, mach_msg_type_number_t invalCnt)
{
	struct logmsg_s *lm, *lm_walk;
	mach_msg_type_number_t data_left = invalCnt;

	if (inval == 0) {
		return 0;
	}

	for (lm_walk = (struct logmsg_s *)inval; (data_left > 0) && (lm_walk->obj_sz <= data_left); lm_walk = ((void *)lm_walk + lm_walk->obj_sz)) {
		if (!launchd_assumes(lm = malloc(lm_walk->obj_sz))) {
			continue;
		}

		memcpy(lm, lm_walk, lm_walk->obj_sz);
		lm->sender_uid = forward_uid;
		lm->sender_gid = forward_gid;

		lm->from_name += (size_t)lm;
		lm->about_name += (size_t)lm;
		lm->msg += (size_t)lm;
		lm->session_name += (size_t)lm;

		STAILQ_INSERT_TAIL(&logmsg_queue, lm, sqe);
		logmsg_queue_sz += lm->obj_sz;
		logmsg_queue_cnt++;

		data_left -= lm->obj_sz;
	}

	mig_deallocate(inval, invalCnt);

	return 0;
}

kern_return_t
runtime_log_drain(mach_port_t srp, vm_offset_t *outval, mach_msg_type_number_t *outvalCnt)
{
	if (logmsg_queue_cnt == 0) {
		launchd_assumes(STAILQ_EMPTY(&logmsg_queue));
		launchd_assumes(drain_reply_port == 0);

		drain_reply_port = srp;
		launchd_assumes(launchd_mport_notify_req(drain_reply_port, MACH_NOTIFY_DEAD_NAME) == KERN_SUCCESS);

		return MIG_NO_REPLY;
	}

	return runtime_log_pack(outval, outvalCnt);
}

/*
 * We should break this into two reference counts.
 *
 * One for hard references that would prevent exiting.
 * One for soft references that would only prevent idle exiting.
 *
 * In the long run, reference counting should completely automate when a
 * process can and should exit.
 */
void
runtime_add_ref(void)
{
	runtime_busy_cnt++;
}

void
runtime_del_ref(void)
{
	runtime_busy_cnt--;
}
