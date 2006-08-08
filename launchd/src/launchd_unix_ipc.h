#ifndef __LAUNCHD_UNIX_IPC__
#define __LAUNCHD_UNIX_IPC__
/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

struct conncb {
	kq_callback kqconn_callback;
	SLIST_ENTRY(conncb) sle;
	launch_t conn;
	struct jobcb *j;
	int disabled_batch:1, futureflags:31;
};

extern char *sockpath;

void ipc_open(int fd, struct jobcb *j);
void ipc_close(struct conncb *c);
void ipc_callback(void *, struct kevent *);
void ipc_readmsg(launch_data_t msg, void *context);
void ipc_revoke_fds(launch_data_t o);
void ipc_close_fds(launch_data_t o);
void ipc_clean_up(void);
void ipc_server_init(int *, size_t);

#endif
