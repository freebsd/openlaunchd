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

#include "config.h"
#include "liblaunch_public.h"
#include "liblaunch_private.h"
#include "liblaunch_internal.h"

#include <mach/mach.h>
#include <libkern/OSByteOrder.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <assert.h>

#include "libbootstrap_public.h"
#include "libvproc_public.h"
#include "libvproc_private.h"
#include "libvproc_internal.h"

/* __OSBogusByteSwap__() must not really exist in the symbol namespace
 * in order for the following to generate an error at build time.
 */
extern void __OSBogusByteSwap__(void);

#define host2big(x)				\
	({ typeof (x) _X, _x = (x);		\
	 switch (sizeof(_x)) {			\
	 case 8:				\
	 	_X = OSSwapHostToBigInt64(_x);	\
	 	break;				\
	 case 4:				\
	 	_X = OSSwapHostToBigInt32(_x);	\
	 	break;				\
	 case 2:				\
	 	_X = OSSwapHostToBigInt16(_x);	\
	 	break;				\
	 case 1:				\
	 	_X = _x;			\
		break;				\
	 default:				\
	 	__OSBogusByteSwap__();		\
		break;				\
	 }					\
	 _X;					\
	 })


#define big2host(x)				\
	({ typeof (x) _X, _x = (x);		\
	 switch (sizeof(_x)) {			\
	 case 8:				\
	 	_X = OSSwapBigToHostInt64(_x);	\
	 	break;				\
	 case 4:				\
	 	_X = OSSwapBigToHostInt32(_x);	\
	 	break;				\
	 case 2:				\
	 	_X = OSSwapBigToHostInt16(_x);	\
	 	break;				\
	 case 1:				\
	 	_X = _x;			\
		break;				\
	 default:				\
	 	__OSBogusByteSwap__();		\
		break;				\
	 }					\
	 _X;					\
	 })


struct launch_msg_header {
	uint64_t magic;
	uint64_t len;
};

#define LAUNCH_MSG_HEADER_MAGIC 0xD2FEA02366B39A41ull

struct _launch_data {
	uint64_t type;
	union {
		struct {
			union {
				launch_data_t *_array;
				char *string;
				void *opaque;
				int64_t __junk;
			};
			union {
				uint64_t _array_cnt;
				uint64_t string_len;
				uint64_t opaque_size;
			};
		};
		int fd;
		mach_port_t mp;
		int err;
		long long number;
		uint32_t boolean; /* We'd use 'bool' but this struct needs to be used under Rosetta, and sizeof(bool) is different between PowerPC and Intel */
		double float_num;
	};
};

struct _launch {
	void	*sendbuf;
	int	*sendfds;
	void	*recvbuf;
	int	*recvfds;
	size_t	sendlen;
	size_t	sendfdcnt;
	size_t	recvlen;
	size_t	recvfdcnt;
	int	fd;
};

static launch_data_t launch_data_array_pop_first(launch_data_t where);
static int _fd(int fd);
static void launch_client_init(void);
static void launch_msg_getmsgs(launch_data_t m, void *context);
static launch_data_t launch_msg_internal(launch_data_t d);
static void launch_mach_checkin_service(launch_data_t obj, const char *key, void *context);

static pthread_once_t _lc_once = PTHREAD_ONCE_INIT;

static struct _launch_client {
	pthread_mutex_t mtx;
	launch_t	l;
	launch_data_t	async_resp;
} *_lc = NULL;

void
launch_client_init(void)
{
	struct sockaddr_un sun;
	char *where = getenv(LAUNCHD_SOCKET_ENV);
	char *_launchd_fd = getenv(LAUNCHD_TRUSTED_FD_ENV);
	int dfd, lfd = -1;
	name_t spath;
	
	_lc = calloc(1, sizeof(struct _launch_client));

	if (!_lc)
		return;

	pthread_mutex_init(&_lc->mtx, NULL);

	if (_launchd_fd) {
		lfd = strtol(_launchd_fd, NULL, 10);
		if ((dfd = dup(lfd)) >= 0) {
			close(dfd);
			_fd(lfd);
		} else {
			lfd = -1;
		}
		unsetenv(LAUNCHD_TRUSTED_FD_ENV);
	}
	if (lfd == -1) {
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		
		if (where && where[0] != '\0') {
			strncpy(sun.sun_path, where, sizeof(sun.sun_path));
		} else if (!getenv("SUDO_COMMAND") && _vprocmgr_getsocket(spath) == 0) {
			size_t min_len;

			min_len = sizeof(sun.sun_path) < sizeof(spath) ? sizeof(sun.sun_path) : sizeof(spath);

			strncpy(sun.sun_path, spath, min_len);
		} else {
			strncpy(sun.sun_path, LAUNCHD_SOCK_PREFIX "/sock", sizeof(sun.sun_path));
		}

		if ((lfd = _fd(socket(AF_UNIX, SOCK_STREAM, 0))) == -1)
			goto out_bad;
		if (-1 == connect(lfd, (struct sockaddr *)&sun, sizeof(sun)))
			goto out_bad;
	}
	if (!(_lc->l = launchd_fdopen(lfd)))
		goto out_bad;
	if (!(_lc->async_resp = launch_data_alloc(LAUNCH_DATA_ARRAY)))
		goto out_bad;

	return;
out_bad:
	if (_lc->l)
		launchd_close(_lc->l, close);
	else if (lfd != -1)
		close(lfd);
	if (_lc)
		free(_lc);
	_lc = NULL;
}

launch_data_t
launch_data_alloc(launch_data_type_t t)
{
	launch_data_t d = calloc(1, sizeof(struct _launch));

	if (d) {
		d->type = t;
		switch (t) {
		case LAUNCH_DATA_DICTIONARY:
		case LAUNCH_DATA_ARRAY:
			d->_array = malloc(0);
			break;
		default:
			break;
		}
	}

	return d;
}

launch_data_type_t
launch_data_get_type(launch_data_t d)
{
	return d->type;
}

void
launch_data_free(launch_data_t d)
{
	size_t i;

	switch (d->type) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < d->_array_cnt; i++)
			launch_data_free(d->_array[i]);
		free(d->_array);
		break;
	case LAUNCH_DATA_STRING:
		if (d->string)
			free(d->string);
		break;
	case LAUNCH_DATA_OPAQUE:
		if (d->opaque)
			free(d->opaque);
		break;
	default:
		break;
	}
	free(d);
}

size_t
launch_data_dict_get_count(launch_data_t dict)
{
	return dict->_array_cnt / 2;
}


bool
launch_data_dict_insert(launch_data_t dict, launch_data_t what, const char *key)
{
	size_t i;
	launch_data_t thekey = launch_data_alloc(LAUNCH_DATA_STRING);

	launch_data_set_string(thekey, key);

	for (i = 0; i < dict->_array_cnt; i += 2) {
		if (!strcasecmp(key, dict->_array[i]->string)) {
			launch_data_array_set_index(dict, thekey, i);
			launch_data_array_set_index(dict, what, i + 1);
			return true;
		}
	}
	launch_data_array_set_index(dict, thekey, i);
	launch_data_array_set_index(dict, what, i + 1);
	return true;
}

launch_data_t
launch_data_dict_lookup(launch_data_t dict, const char *key)
{
	size_t i;

	if (LAUNCH_DATA_DICTIONARY != dict->type)
		return NULL;

	for (i = 0; i < dict->_array_cnt; i += 2) {
		if (!strcasecmp(key, dict->_array[i]->string))
			return dict->_array[i + 1];
	}

	return NULL;
}

bool
launch_data_dict_remove(launch_data_t dict, const char *key)
{
	size_t i;

	for (i = 0; i < dict->_array_cnt; i += 2) {
		if (!strcasecmp(key, dict->_array[i]->string))
			break;
	}
	if (i == dict->_array_cnt)
		return false;
	launch_data_free(dict->_array[i]);
	launch_data_free(dict->_array[i + 1]);
	memmove(dict->_array + i, dict->_array + i + 2, (dict->_array_cnt - (i + 2)) * sizeof(launch_data_t));
	dict->_array_cnt -= 2;
	return true;
}

void
launch_data_dict_iterate(launch_data_t dict, void (*cb)(launch_data_t, const char *, void *), void *context)
{
	size_t i;

	if (LAUNCH_DATA_DICTIONARY != dict->type)
		return;

	for (i = 0; i < dict->_array_cnt; i += 2)
		cb(dict->_array[i + 1], dict->_array[i]->string, context);
}

bool
launch_data_array_set_index(launch_data_t where, launch_data_t what, size_t ind)
{
	if ((ind + 1) >= where->_array_cnt) {
		where->_array = reallocf(where->_array, (ind + 1) * sizeof(launch_data_t));
		memset(where->_array + where->_array_cnt, 0, (ind + 1 - where->_array_cnt) * sizeof(launch_data_t));
		where->_array_cnt = ind + 1;
	}

	if (where->_array[ind])
		launch_data_free(where->_array[ind]);
	where->_array[ind] = what;
	return true;
}

launch_data_t
launch_data_array_get_index(launch_data_t where, size_t ind)
{
	if (LAUNCH_DATA_ARRAY != where->type)
		return NULL;
	if (ind < where->_array_cnt)
		return where->_array[ind];
	return NULL;
}

launch_data_t
launch_data_array_pop_first(launch_data_t where)
{
	launch_data_t r = NULL;

	if (where->_array_cnt > 0) {
		r = where->_array[0];
		memmove(where->_array, where->_array + 1, (where->_array_cnt - 1) * sizeof(launch_data_t));
		where->_array_cnt--;
	}
	return r;
}

size_t
launch_data_array_get_count(launch_data_t where)
{
	if (LAUNCH_DATA_ARRAY != where->type)
		return 0;
	return where->_array_cnt;
}

bool
launch_data_set_errno(launch_data_t d, int e)
{
	d->err = e;
	return true;
}

bool
launch_data_set_fd(launch_data_t d, int fd)
{
	d->fd = fd;
	return true;
}

bool
launch_data_set_machport(launch_data_t d, mach_port_t p)
{
	d->mp = p;
	return true;
}

bool
launch_data_set_integer(launch_data_t d, long long n)
{
	d->number = n;
	return true;
}

bool
launch_data_set_bool(launch_data_t d, bool b)
{
	d->boolean = b;
	return true;
}

bool
launch_data_set_real(launch_data_t d, double n)
{
	d->float_num = n;
	return true;
}

bool
launch_data_set_string(launch_data_t d, const char *s)
{
	if (d->string)
		free(d->string);
	d->string = strdup(s);
	if (d->string) {
		d->string_len = strlen(d->string);
		return true;
	}
	return false;
}

bool
launch_data_set_opaque(launch_data_t d, const void *o, size_t os)
{
	d->opaque_size = os;
	if (d->opaque)
		free(d->opaque);
	d->opaque = malloc(os);
	if (d->opaque) {
		memcpy(d->opaque, o, os);
		return true;
	}
	return false;
}

int
launch_data_get_errno(launch_data_t d)
{
	return d->err;
}

int
launch_data_get_fd(launch_data_t d)
{
	return d->fd;
}

mach_port_t
launch_data_get_machport(launch_data_t d)
{
	return d->mp;
}

long long
launch_data_get_integer(launch_data_t d)
{
	return d->number;
}

bool
launch_data_get_bool(launch_data_t d)
{
	return d->boolean;
}

double
launch_data_get_real(launch_data_t d)
{
	return d->float_num;
}

const char *
launch_data_get_string(launch_data_t d)
{
	if (LAUNCH_DATA_STRING != d->type)
		return NULL;
	return d->string;
}

void *
launch_data_get_opaque(launch_data_t d)
{
	if (LAUNCH_DATA_OPAQUE != d->type)
		return NULL;
	return d->opaque;
}

size_t
launch_data_get_opaque_size(launch_data_t d)
{
	return d->opaque_size;
}

int
launchd_getfd(launch_t l)
{
	return l->fd;
}

launch_t
launchd_fdopen(int fd)
{
	launch_t c;

	c = calloc(1, sizeof(struct _launch));
	if (!c)
		return NULL;

	c->fd = fd;

	fcntl(fd, F_SETFL, O_NONBLOCK);

	if ((c->sendbuf = malloc(0)) == NULL)
		goto out_bad;
	if ((c->sendfds = malloc(0)) == NULL)
		goto out_bad;
	if ((c->recvbuf = malloc(0)) == NULL)
		goto out_bad;
	if ((c->recvfds = malloc(0)) == NULL)
		goto out_bad;

	return c;

out_bad:
	if (c->sendbuf)
		free(c->sendbuf);
	if (c->sendfds)
		free(c->sendfds);
	if (c->recvbuf)
		free(c->recvbuf);
	if (c->recvfds)
		free(c->recvfds);
	free(c);
	return NULL;
}

void
launchd_close(launch_t lh, typeof(close) closefunc)
{
	if (lh->sendbuf)
		free(lh->sendbuf);
	if (lh->sendfds)
		free(lh->sendfds);
	if (lh->recvbuf)
		free(lh->recvbuf);
	if (lh->recvfds)
		free(lh->recvfds);
	closefunc(lh->fd);
	free(lh);
}

#define ROUND_TO_64BIT_WORD_SIZE(x)	((x + 7) & ~7)

size_t
launch_data_pack(launch_data_t d, void *where, size_t len, int *fd_where, size_t *fd_cnt)
{
	launch_data_t o_in_w = where;
	size_t i, rsz, total_data_len = sizeof(struct _launch_data);

	if (total_data_len > len) {
		return 0;
	}

	where += total_data_len;

	o_in_w->type = host2big(d->type);

	switch (d->type) {
	case LAUNCH_DATA_INTEGER:
		o_in_w->number = host2big(d->number);
		break;
	case LAUNCH_DATA_REAL:
		o_in_w->float_num = host2big(d->float_num);
		break;
	case LAUNCH_DATA_BOOL:
		o_in_w->boolean = host2big(d->boolean);
		break;
	case LAUNCH_DATA_ERRNO:
		o_in_w->err = host2big(d->err);
		break;
	case LAUNCH_DATA_FD:
		o_in_w->fd = host2big(d->fd);
		if (fd_where && d->fd != -1) {
			fd_where[*fd_cnt] = d->fd;
			(*fd_cnt)++;
		}
		break;
	case LAUNCH_DATA_STRING:
		o_in_w->string_len = host2big(d->string_len);
		total_data_len += ROUND_TO_64BIT_WORD_SIZE(strlen(d->string) + 1);
		if (total_data_len > len) {
			return 0;
		}
		memcpy(where, d->string, strlen(d->string) + 1);
		break;
	case LAUNCH_DATA_OPAQUE:
		o_in_w->opaque_size = host2big(d->opaque_size);
		total_data_len += ROUND_TO_64BIT_WORD_SIZE(d->opaque_size);
		if (total_data_len > len) {
			return 0;
		}
		memcpy(where, d->opaque, d->opaque_size);
		break;
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		o_in_w->_array_cnt = host2big(d->_array_cnt);
		total_data_len += d->_array_cnt * sizeof(uint64_t);
		if (total_data_len > len) {
			return 0;
		}

		where += d->_array_cnt * sizeof(uint64_t);

		for (i = 0; i < d->_array_cnt; i++) {
			rsz = launch_data_pack(d->_array[i], where, len - total_data_len, fd_where, fd_cnt);
			if (rsz == 0) {
				return 0;
			}
			where += rsz;
			total_data_len += rsz;
		}
		break;
	default:
		break;
	}

	return total_data_len;
}

launch_data_t
launch_data_unpack(void *data, size_t data_size, int *fds, size_t fd_cnt, size_t *data_offset, size_t *fdoffset)
{
	launch_data_t r = data + *data_offset;
	size_t i, tmpcnt;

	if ((data_size - *data_offset) < sizeof(struct _launch_data))
		return NULL;
	*data_offset += sizeof(struct _launch_data);

	switch (big2host(r->type)) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		tmpcnt = big2host(r->_array_cnt);
		if ((data_size - *data_offset) < (tmpcnt * sizeof(uint64_t))) {
			errno = EAGAIN;
			return NULL;
		}
		r->_array = data + *data_offset;
		*data_offset += tmpcnt * sizeof(uint64_t);
		for (i = 0; i < tmpcnt; i++) {
			r->_array[i] = launch_data_unpack(data, data_size, fds, fd_cnt, data_offset, fdoffset);
			if (r->_array[i] == NULL)
				return NULL;
		}
		r->_array_cnt = tmpcnt;
		break;
	case LAUNCH_DATA_STRING:
		tmpcnt = big2host(r->string_len);
		if ((data_size - *data_offset) < (tmpcnt + 1)) {
			errno = EAGAIN;
			return NULL;
		}
		r->string = data + *data_offset;
		r->string_len = tmpcnt;
		*data_offset += ROUND_TO_64BIT_WORD_SIZE(tmpcnt + 1);
		break;
	case LAUNCH_DATA_OPAQUE:
		tmpcnt = big2host(r->opaque_size);
		if ((data_size - *data_offset) < tmpcnt) {
			errno = EAGAIN;
			return NULL;
		}
		r->opaque = data + *data_offset;
		r->opaque_size = tmpcnt;
		*data_offset += ROUND_TO_64BIT_WORD_SIZE(tmpcnt);
		break;
	case LAUNCH_DATA_FD:
		if (r->fd != -1 && fd_cnt > *fdoffset) {
			r->fd = _fd(fds[*fdoffset]);
			*fdoffset += 1;
		}
		break;
	case LAUNCH_DATA_INTEGER:
		r->number = big2host(r->number);
		break;
	case LAUNCH_DATA_REAL:
		r->float_num = big2host(r->float_num);
		break;
	case LAUNCH_DATA_BOOL:
		r->boolean = big2host(r->boolean);
		break;
	case LAUNCH_DATA_ERRNO:
		r->err = big2host(r->err);
	case LAUNCH_DATA_MACHPORT:
		break;
	default:
		errno = EINVAL;
		return NULL;
		break;
	}

	r->type = big2host(r->type);

	return r;
}

int launchd_msg_send(launch_t lh, launch_data_t d)
{
	struct launch_msg_header lmh;
	struct cmsghdr *cm = NULL;
	struct msghdr mh;
	struct iovec iov[2];
	size_t sentctrllen = 0;
	int r;

	memset(&mh, 0, sizeof(mh));

	/* confirm that the next hack works */
	assert((d && lh->sendlen == 0) || (!d && lh->sendlen));

	if (d) {
		size_t fd_slots_used = 0;
		size_t good_enough_size = 10 * 1024 * 1024;
		uint64_t msglen;

		/* hack, see the above assert to verify "correctness" */
		free(lh->sendbuf);
		lh->sendbuf = malloc(good_enough_size);
		free(lh->sendfds);
		lh->sendfds = malloc(4 * 1024);

		lh->sendlen = launch_data_pack(d, lh->sendbuf, good_enough_size, lh->sendfds, &fd_slots_used);

		if (lh->sendlen == 0) {
			errno = ENOMEM;
			return -1;
		}

		lh->sendfdcnt = fd_slots_used;

		msglen = lh->sendlen + sizeof(struct launch_msg_header); /* type promotion to make the host2big() macro work right */
		lmh.len = host2big(msglen);
		lmh.magic = host2big(LAUNCH_MSG_HEADER_MAGIC);

		iov[0].iov_base = &lmh;
		iov[0].iov_len = sizeof(lmh);
		mh.msg_iov = iov;
		mh.msg_iovlen = 2;
	} else {
		mh.msg_iov = iov + 1;
		mh.msg_iovlen = 1;
	}

	iov[1].iov_base = lh->sendbuf;
	iov[1].iov_len = lh->sendlen;


	if (lh->sendfdcnt > 0) {
		sentctrllen = mh.msg_controllen = CMSG_SPACE(lh->sendfdcnt * sizeof(int));
		cm = alloca(mh.msg_controllen);
		mh.msg_control = cm;

		memset(cm, 0, mh.msg_controllen);

		cm->cmsg_len = CMSG_LEN(lh->sendfdcnt * sizeof(int));
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;

		memcpy(CMSG_DATA(cm), lh->sendfds, lh->sendfdcnt * sizeof(int));
	}

	if ((r = sendmsg(lh->fd, &mh, 0)) == -1) {
		return -1;
	} else if (r == 0) {
		errno = ECONNRESET;
		return -1;
	} else if (sentctrllen != mh.msg_controllen) {
		errno = ECONNRESET;
		return -1;
	}

	if (d) {
		r -= sizeof(struct launch_msg_header);
	}

	lh->sendlen -= r;
	if (lh->sendlen > 0) {
		memmove(lh->sendbuf, lh->sendbuf + r, lh->sendlen);
	} else {
		free(lh->sendbuf);
		lh->sendbuf = malloc(0);
	}

	lh->sendfdcnt = 0;
	free(lh->sendfds);
	lh->sendfds = malloc(0);

	if (lh->sendlen > 0) {
		errno = EAGAIN;
		return -1;
	}

	return 0;
}


int
launch_get_fd(void)
{
	pthread_once(&_lc_once, launch_client_init);

	if (!_lc) {
		errno = ENOTCONN;
		return -1;
	}

	return _lc->l->fd;
}

void
launch_msg_getmsgs(launch_data_t m, void *context)
{
	launch_data_t async_resp, *sync_resp = context;
	
	if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(m)) && (async_resp = launch_data_dict_lookup(m, LAUNCHD_ASYNC_MSG_KEY))) {
		launch_data_array_set_index(_lc->async_resp, launch_data_copy(async_resp), launch_data_array_get_count(_lc->async_resp));
	} else {
		*sync_resp = launch_data_copy(m);
	}
}

void
launch_mach_checkin_service(launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	kern_return_t result;
	mach_port_t p;
	name_t srvnm;

	strlcpy(srvnm, key, sizeof(srvnm));

	result = bootstrap_check_in(bootstrap_port, srvnm, &p);

	if (result == BOOTSTRAP_SUCCESS)
		launch_data_set_machport(obj, p);
}

launch_data_t
launch_msg(launch_data_t d)
{
	launch_data_t mps, r = launch_msg_internal(d);

	if (launch_data_get_type(d) == LAUNCH_DATA_STRING) {
		if (strcmp(launch_data_get_string(d), LAUNCH_KEY_CHECKIN) != 0)
			return r;
		if (r == NULL)
			return r;
		if (launch_data_get_type(r) != LAUNCH_DATA_DICTIONARY)
			return r;
		mps = launch_data_dict_lookup(r, LAUNCH_JOBKEY_MACHSERVICES);
		if (mps == NULL)
			return r;
		launch_data_dict_iterate(mps, launch_mach_checkin_service, NULL);
	}

	return r;
}

launch_data_t
launch_msg_internal(launch_data_t d)
{
	launch_data_t resp = NULL;

	if (d && (launch_data_get_type(d) == LAUNCH_DATA_STRING)
			&& (strcmp(launch_data_get_string(d), LAUNCH_KEY_GETJOBS) == 0)
			&& vproc_swap_complex(NULL, VPROC_GSK_ALLJOBS, NULL, &resp) == NULL) {
		return resp;
	}

	pthread_once(&_lc_once, launch_client_init);

	if (!_lc) {
		errno = ENOTCONN;
		return NULL;
	}

	pthread_mutex_lock(&_lc->mtx);

	if (d && launchd_msg_send(_lc->l, d) == -1) {
		do {
			if (errno != EAGAIN)
				goto out;
		} while (launchd_msg_send(_lc->l, NULL) == -1);
	}

	while (resp == NULL) {
		if (d == NULL && launch_data_array_get_count(_lc->async_resp) > 0) {
			resp = launch_data_array_pop_first(_lc->async_resp);
			goto out;
		}
		if (launchd_msg_recv(_lc->l, launch_msg_getmsgs, &resp) == -1) {
			if (errno != EAGAIN) {
				goto out;
			} else if (d == NULL) {
				errno = 0;
				goto out;
			} else {
				fd_set rfds;

				FD_ZERO(&rfds);
				FD_SET(_lc->l->fd, &rfds);
			
				select(_lc->l->fd + 1, &rfds, NULL, NULL, NULL);
			}
		}
	}

out:
	pthread_mutex_unlock(&_lc->mtx);

	return resp;
}

int launchd_msg_recv(launch_t lh, void (*cb)(launch_data_t, void *), void *context)
{
	struct cmsghdr *cm = alloca(4096); 
	launch_data_t rmsg = NULL;
	size_t data_offset, fd_offset;
	struct msghdr mh;
	struct iovec iov;
	int r;

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	lh->recvbuf = reallocf(lh->recvbuf, lh->recvlen + 8*1024);

	iov.iov_base = lh->recvbuf + lh->recvlen;
	iov.iov_len = 8*1024;
	mh.msg_control = cm;
	mh.msg_controllen = 4096;

	if ((r = recvmsg(lh->fd, &mh, 0)) == -1)
		return -1;
	if (r == 0) {
		errno = ECONNRESET;
		return -1;
	}
	if (mh.msg_flags & MSG_CTRUNC) {
		errno = ECONNABORTED;
		return -1;
	}
	lh->recvlen += r;
	if (mh.msg_controllen > 0) {
		lh->recvfds = reallocf(lh->recvfds, lh->recvfdcnt * sizeof(int) + mh.msg_controllen - sizeof(struct cmsghdr));
		memcpy(lh->recvfds + lh->recvfdcnt, CMSG_DATA(cm), mh.msg_controllen - sizeof(struct cmsghdr));
		lh->recvfdcnt += (mh.msg_controllen - sizeof(struct cmsghdr)) / sizeof(int);
	}

	r = 0;

	while (lh->recvlen > 0) {
		struct launch_msg_header *lmhp = lh->recvbuf;
		uint64_t tmplen;
		data_offset = sizeof(struct launch_msg_header);
		fd_offset = 0;

		if (lh->recvlen < sizeof(struct launch_msg_header))
			goto need_more_data;

		tmplen = big2host(lmhp->len);

		if (big2host(lmhp->magic) != LAUNCH_MSG_HEADER_MAGIC || tmplen <= sizeof(struct launch_msg_header)) {
			errno = EBADRPC;
			goto out_bad;
		}

		if (lh->recvlen < tmplen) {
			goto need_more_data;
		}

		if ((rmsg = launch_data_unpack(lh->recvbuf, lh->recvlen, lh->recvfds, lh->recvfdcnt, &data_offset, &fd_offset)) == NULL) {
			errno = EBADRPC;
			goto out_bad;
		}

		cb(rmsg, context);

		lh->recvlen -= data_offset;
		if (lh->recvlen > 0) {
			memmove(lh->recvbuf, lh->recvbuf + data_offset, lh->recvlen);
		} else {
			free(lh->recvbuf);
			lh->recvbuf = malloc(0);
		}

		lh->recvfdcnt -= fd_offset;
		if (lh->recvfdcnt > 0) {
			memmove(lh->recvfds, lh->recvfds + fd_offset, lh->recvfdcnt * sizeof(int));
		} else {
			free(lh->recvfds);
			lh->recvfds = malloc(0);
		}
	}

	return r;

need_more_data:
	errno = EAGAIN;
out_bad:
	return -1;
}

launch_data_t launch_data_copy(launch_data_t o)
{
	launch_data_t r = launch_data_alloc(o->type);
	size_t i;

	free(r->_array);
	memcpy(r, o, sizeof(struct _launch_data));

	switch (o->type) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		r->_array = calloc(1, o->_array_cnt * sizeof(launch_data_t));
		for (i = 0; i < o->_array_cnt; i++) {
			if (o->_array[i])
				r->_array[i] = launch_data_copy(o->_array[i]);
		}
		break;
	case LAUNCH_DATA_STRING:
		r->string = strdup(o->string);
		break;
	case LAUNCH_DATA_OPAQUE:
		r->opaque = malloc(o->opaque_size);
		memcpy(r->opaque, o->opaque, o->opaque_size);
		break;
	default:
		break;
	}

	return r;
}

void
launchd_batch_enable(bool b)
{
	int64_t val = b;

	vproc_swap_integer(NULL, VPROC_GSK_GLOBAL_ON_DEMAND, &val, NULL);
}

bool
launchd_batch_query(void)
{
	int64_t val;

	if (vproc_swap_integer(NULL, VPROC_GSK_GLOBAL_ON_DEMAND, NULL, &val) == NULL) {
		return (bool)val;
	}

	return false;
}

static int _fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}

launch_data_t launch_data_new_errno(int e)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_ERRNO);

	if (r)
		launch_data_set_errno(r, e);

	return r;
}

launch_data_t launch_data_new_fd(int fd)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_FD);

	if (r)
		launch_data_set_fd(r, fd);

	return r;
}

launch_data_t launch_data_new_machport(mach_port_t p)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_MACHPORT);

	if (r)
		launch_data_set_machport(r, p);

	return r;
}

launch_data_t launch_data_new_integer(long long n)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_INTEGER);

	if (r)
		launch_data_set_integer(r, n);

	return r;
}

launch_data_t launch_data_new_bool(bool b)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_BOOL);

	if (r)
		launch_data_set_bool(r, b);

	return r;
}

launch_data_t launch_data_new_real(double d)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_REAL);

	if (r)
		launch_data_set_real(r, d);

	return r;
}

launch_data_t launch_data_new_string(const char *s)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_STRING);

	if (r == NULL)
		return NULL;

	if (!launch_data_set_string(r, s)) {
		launch_data_free(r);
		return NULL;
	}

	return r;
}

launch_data_t launch_data_new_opaque(const void *o, size_t os)
{
	launch_data_t r = launch_data_alloc(LAUNCH_DATA_OPAQUE);

	if (r == NULL)
		return NULL;

	if (!launch_data_set_opaque(r, o, os)) {
		launch_data_free(r);
		return NULL;
	}

	return r;
}

void
load_launchd_jobs_at_loginwindow_prompt(int flags __attribute__((unused)), ...)
{
	_vprocmgr_init("LoginWindow");
}

pid_t
create_and_switch_to_per_session_launchd(const char *login __attribute__((unused)), int flags __attribute__((unused)), ...)
{
	mach_port_t bezel_ui_server;
	struct stat sb;
	uid_t target_user = geteuid() ? geteuid() : getuid();

	if (_vprocmgr_move_subset_to_user(target_user, "Aqua")) {
		return -1;
	}

#define BEZEL_UI_PATH "/System/Library/LoginPlugins/BezelServices.loginPlugin/Contents/Resources/BezelUI/BezelUIServer"
#define BEZEL_UI_PLIST "/System/Library/LaunchAgents/com.apple.BezelUIServer.plist"
#define BEZEL_UI_SERVICE "BezelUI"

	if (!(stat(BEZEL_UI_PLIST, &sb) == 0 && S_ISREG(sb.st_mode))) {
		if (bootstrap_create_server(bootstrap_port, BEZEL_UI_PATH, target_user, true, &bezel_ui_server) == BOOTSTRAP_SUCCESS) {
			mach_port_t srv;

			if (bootstrap_create_service(bezel_ui_server, BEZEL_UI_SERVICE, &srv) == BOOTSTRAP_SUCCESS) {
				mach_port_deallocate(mach_task_self(), srv);
			}

			mach_port_deallocate(mach_task_self(), bezel_ui_server);
		}
	}

	return 1;
}
