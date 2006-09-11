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
#include <sys/time.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <bsm/libbsm.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>

#include "launchd_runtime.h"

#include "launchd_internalServer.h"
#include "launchd_internal.h"
#include "notifyServer.h"

/* We shouldn't be including these */
#include "launch.h"
#include "launchd.h"
#include "launchd_core_logic.h"
#include "bootstrapServer.h"

static mach_port_t ipc_port_set = MACH_PORT_NULL;
static mach_port_t demand_port_set = MACH_PORT_NULL;
static mach_port_t launchd_internal_port = MACH_PORT_NULL;
static int mainkq = -1;
static int asynckq = -1;

static pthread_t kqueue_demand_thread;
static pthread_t demand_thread;;

static void *mport_demand_loop(void *arg);
static void *kqueue_demand_loop(void *arg);

static void async_callback(void);
static kq_callback kqasync_callback = (kq_callback)async_callback;

void
launchd_runtime_init(void)
{
	pthread_attr_t attr;

	launchd_assert((mainkq = kqueue()) != -1);
	launchd_assert((asynckq = kqueue()) != -1);

	launchd_assert(kevent_mod(asynckq, EVFILT_READ, EV_ADD, 0, 0, &kqasync_callback) != -1);

	launchd_assert((errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &demand_port_set)) == KERN_SUCCESS);
	launchd_assert((errno = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &ipc_port_set)) == KERN_SUCCESS);

	launchd_assert(launchd_mport_create_recv(&launchd_internal_port) == KERN_SUCCESS);
	launchd_assert(launchd_mport_make_send(launchd_internal_port) == KERN_SUCCESS);
	launchd_assert((errno = mach_port_move_member(mach_task_self(), launchd_internal_port, ipc_port_set)) == KERN_SUCCESS);

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

kern_return_t
x_handle_mport(mach_port_t junk __attribute__((unused)))
{
	mach_port_name_array_t members;
	mach_msg_type_number_t membersCnt;
	mach_port_status_t status;
	mach_msg_type_number_t statusCnt;
	struct kevent kev;
	unsigned int i;

	if (!launchd_assumes(mach_port_get_set_status(mach_task_self(), demand_port_set, &members, &membersCnt) == KERN_SUCCESS))
		return 1;

	for (i = 0; i < membersCnt; i++) {
		statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
		if (mach_port_get_attributes(mach_task_self(), members[i], MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status,
					&statusCnt) != KERN_SUCCESS) {
			continue;
		}
		if (status.mps_msgcount) {
			EV_SET(&kev, members[i], EVFILT_MACHPORT, 0, 0, 0, job_find_by_port(members[i]));
			(*((kq_callback *)kev.udata))(kev.udata, &kev);
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

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(mainkq, &rfds);
		if (launchd_assumes(select(mainkq + 1, &rfds, NULL, NULL, NULL) == 1))
			launchd_assumes(handle_kqueue(launchd_internal_port, mainkq) == 0);
	}

	return NULL;
}

kern_return_t
x_handle_kqueue(mach_port_t junk __attribute__((unused)), integer_t fd)
{
	struct timespec ts = { 0, 0 };
	struct kevent kev;
	int kevr;

	launchd_assumes((kevr = kevent(fd, NULL, 0, &kev, 1, &ts)) != -1);

	if (kevr == 1)
		(*((kq_callback *)kev.udata))(kev.udata, &kev);

	launchd_post_kevent();

	return 0;
}



void
launchd_runtime(void)
{
	mach_msg_return_t msgr;

	for (;;) {
		msgr = mach_msg_server(launchd_internal_demux, 10*1024, ipc_port_set,
				MACH_RCV_LARGE |
				MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT) |
				MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
		launchd_assumes(msgr == MACH_MSG_SUCCESS);
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
	mach_port_mscount_t msgc = (which == MACH_NOTIFY_NO_SENDERS) ? 1 : 0;
	mach_port_t previous, where = (which == MACH_NOTIFY_NO_SENDERS) ? name : launchd_internal_port;

	if (which == MACH_NOTIFY_NO_SENDERS) {
		/* Always make sure the send count is zero, in case a receive right is reused */
		errno = mach_port_set_mscount(mach_task_self(), name, 0);
		if (errno != KERN_SUCCESS)
			return errno;
	}

	errno = mach_port_request_notification(mach_task_self(), name, which, msgc, where,
			MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);

	if (errno == 0 && previous != MACH_PORT_NULL)
		launchd_assumes(launchd_mport_deallocate(previous) == KERN_SUCCESS);

	return errno;
}

kern_return_t
launchd_mport_request_callback(mach_port_t name, void *obj, bool readmsg)
{
	mach_port_t target_set = MACH_PORT_NULL;

	if (obj) {
		target_set = readmsg ? ipc_port_set : demand_port_set;
	}

	return errno = mach_port_move_member(mach_task_self(), name, target_set);
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
kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	int q = mainkq;

	if (EVFILT_TIMER == filter || EVFILT_VNODE == filter)
		q = asynckq;

	if (flags & EV_ADD && !launchd_assumes(udata != NULL)) {
		errno = EINVAL;
		return -1;
	}

	EV_SET(&kev, ident, filter, flags, fflags, data, udata);

	return kevent(q, &kev, 1, NULL, 0, NULL);
}

void
async_callback(void)
{
	struct timespec timeout = { 0, 0 };
	struct kevent kev;

	if (launchd_assumes(kevent(asynckq, NULL, 0, &kev, 1, &timeout) == 1)) {
		(*((kq_callback *)kev.udata))(kev.udata, &kev);
	}
}

void
runtime_force_on_demand(bool b)
{
	launchd_assumes(kevent_mod(asynckq, EVFILT_READ, b ? EV_DISABLE : EV_ENABLE, 0, 0, &kqasync_callback) != -1);
}

boolean_t
launchd_internal_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply)
{
	if (gc_this_job) {
		job_remove(gc_this_job);
		gc_this_job = NULL;
	}

	if (Request->msgh_local_port == launchd_internal_port) {
		if (launchd_internal_server_routine(Request))
			return launchd_internal_server(Request, Reply);
	} else {
		if (bootstrap_server_routine(Request))
			return bootstrap_server(Request, Reply);
	}

	return notify_server(Request, Reply);
}

kern_return_t
do_mach_notify_port_destroyed(mach_port_t notify, mach_port_t rights)
{
	/* This message is sent to us when a receive right is returned to us. */

	if (!job_ack_port_destruction(root_job, rights)) {
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
	job_t j = job_find_by_port(notify);

	/* This message is sent to us when the last customer of one of our
	 * objects goes away.
	 */

	if (!launchd_assumes(j != NULL))
		return KERN_FAILURE;

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

	if (name == inherited_bootstrap_port) {
		launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);
		inherited_bootstrap_port = MACH_PORT_NULL;
	}

	job_delete_anything_with_port(root_job, name);

	/* A dead-name notification about a port appears to increment the
	 * rights on said port. Let's deallocate it so that we don't leak
	 * dead-name ports.
	 */
	launchd_assumes(launchd_mport_deallocate(name) == KERN_SUCCESS);

	return KERN_SUCCESS;
}
