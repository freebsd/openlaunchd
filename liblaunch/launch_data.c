/*
 * Copyright (c) 2005-2012 Apple Inc. All rights reserved.
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
#include "launch.h"
#include "byteswap.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* NOTE: defined temporarily in liblaunch.c */
extern int _fd(int fd);

launch_data_t
launch_data_alloc(launch_data_type_t t)
{
	launch_data_t d = calloc(1, sizeof(struct _launch_data));
	assert(NULL != d);

	if (d) {
		d->type = t;
		switch (t) {
		case LAUNCH_DATA_DICTIONARY:
		case LAUNCH_DATA_ARRAY:
			d->_array = malloc(0);
			break;
		case LAUNCH_DATA_OPAQUE:
			d->opaque = malloc(0);
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
		for (i = 0; i < d->_array_cnt; i++) {
			if (d->_array[i]) {
				launch_data_free(d->_array[i]);
			}
		}
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

	if (LAUNCH_DATA_DICTIONARY != dict->type) {
		return;
	}

	for (i = 0; i < dict->_array_cnt; i += 2) {
		cb(dict->_array[i + 1], dict->_array[i]->string, context);
	}
}

bool
launch_data_array_set_index(launch_data_t where, launch_data_t what, size_t ind)
{
	if ((ind + 1) >= where->_array_cnt) {
		where->_array = reallocf(where->_array, (ind + 1) * sizeof(launch_data_t));
		memset(where->_array + where->_array_cnt, 0, (ind + 1 - where->_array_cnt) * sizeof(launch_data_t));
		where->_array_cnt = ind + 1;
	}

	if (where->_array[ind]) {
		launch_data_free(where->_array[ind]);
	}

	where->_array[ind] = what;
	return true;
}

launch_data_t
launch_data_array_get_index(launch_data_t where, size_t ind)
{
	if (LAUNCH_DATA_ARRAY != where->type || ind >= where->_array_cnt) {
		return NULL;
	} else {
		return where->_array[ind];
	}
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


#if HAS_MACH
bool
launch_data_set_machport(launch_data_t d, mach_port_t p)
{
	d->mp = p;
	return true;
}
#endif

#define ROUND_TO_64BIT_WORD_SIZE(x)	((x + 7) & ~7)

size_t
launch_data_pack(launch_data_t d, void *where, size_t len, int *fd_where, size_t *fd_cnt)
{
	launch_data_t o_in_w = where;
	size_t i, rsz, node_data_len = sizeof(struct _launch_data);

	if (node_data_len > len) {
		return 0;
	}

	where += node_data_len;

	o_in_w->type = host2wire(d->type);

	size_t pad_len = 0;
	switch (d->type) {
	case LAUNCH_DATA_INTEGER:
		o_in_w->number = host2wire(d->number);
		break;
	case LAUNCH_DATA_REAL:
		o_in_w->float_num = host2wire_f(d->float_num);
		break;
	case LAUNCH_DATA_BOOL:
		o_in_w->boolean = host2wire(d->boolean);
		break;
	case LAUNCH_DATA_ERRNO:
		o_in_w->err = host2wire(d->err);
		break;
	case LAUNCH_DATA_FD:
		o_in_w->fd = host2wire(d->fd);
		if (fd_where && d->fd != -1) {
			fd_where[*fd_cnt] = d->fd;
			(*fd_cnt)++;
		}
		break;
	case LAUNCH_DATA_STRING:
		o_in_w->string_len = host2wire(d->string_len);
		node_data_len += ROUND_TO_64BIT_WORD_SIZE(d->string_len + 1);

		if (node_data_len > len) {
			return 0;
		}
		memcpy(where, d->string, d->string_len + 1);

		/* Zero padded data. */
		pad_len = ROUND_TO_64BIT_WORD_SIZE(d->string_len + 1) - (d->string_len + 1);
		bzero(where + d->string_len + 1, pad_len);

		break;
	case LAUNCH_DATA_OPAQUE:
		o_in_w->opaque_size = host2wire(d->opaque_size);
		node_data_len += ROUND_TO_64BIT_WORD_SIZE(d->opaque_size);
		if (node_data_len > len) {
			return 0;
		}
		memcpy(where, d->opaque, d->opaque_size);

		/* Zero padded data. */
		pad_len = ROUND_TO_64BIT_WORD_SIZE(d->opaque_size) - d->opaque_size;
		bzero(where + d->opaque_size, pad_len);

		break;
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		o_in_w->_array_cnt = host2wire(d->_array_cnt);
		node_data_len += d->_array_cnt * sizeof(uint64_t);
		if (node_data_len > len) {
			return 0;
		}

		where += d->_array_cnt * sizeof(uint64_t);

		for (i = 0; i < d->_array_cnt; i++) {
			rsz = launch_data_pack(d->_array[i], where, len - node_data_len, fd_where, fd_cnt);
			if (rsz == 0) {
				return 0;
			}
			where += rsz;
			node_data_len += rsz;
		}
		break;
	default:
		break;
	}

	return node_data_len;
}

launch_data_t
launch_data_unpack(void *data, size_t data_size, int *fds, size_t fd_cnt, size_t *data_offset, size_t *fdoffset)
{
	launch_data_t r = data + *data_offset;
	size_t i, tmpcnt;

	if ((data_size - *data_offset) < sizeof(struct _launch_data))
		return NULL;
	*data_offset += sizeof(struct _launch_data);

	switch (wire2host(r->type)) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		tmpcnt = wire2host(r->_array_cnt);
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
		tmpcnt = wire2host(r->string_len);
		if ((data_size - *data_offset) < (tmpcnt + 1)) {
			errno = EAGAIN;
			return NULL;
		}
		r->string = data + *data_offset;
		r->string_len = tmpcnt;
		*data_offset += ROUND_TO_64BIT_WORD_SIZE(tmpcnt + 1);
		break;
	case LAUNCH_DATA_OPAQUE:
		tmpcnt = wire2host(r->opaque_size);
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
		r->number = wire2host(r->number);
		break;
	case LAUNCH_DATA_REAL:
		r->float_num = wire2host_f(r->float_num);
		break;
	case LAUNCH_DATA_BOOL:
		r->boolean = wire2host(r->boolean);
		break;
	case LAUNCH_DATA_ERRNO:
		r->err = wire2host(r->err);
#if HAS_MACH
	case LAUNCH_DATA_MACHPORT:
		break;
#endif
	default:
		errno = EINVAL;
		return NULL;
		break;
	}

	r->type = wire2host(r->type);

	return r;
}
