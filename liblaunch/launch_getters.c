/*
 * Copyright (c) 2013 Apple, Inc, R. Tyler Croy, All rights reserved.
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
 */
#include "launch.h"
#include "launch_priv.h"
#include "launch_internal.h"

int
launch_data_get_errno(launch_data_t d)
{
    if (NULL == d) {
	return 0;
    }
	return d->err;
}

int
launch_data_get_fd(launch_data_t d)
{
    if (NULL == d) {
	return 0;
    }
	return d->fd;
}

long long
launch_data_get_integer(launch_data_t d)
{
    if (NULL == d) {
	return 0;
    }
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
	return (l->which == LAUNCHD_USE_CHECKIN_FD) ? l->cifd : l->fd;
}

#if HAS_MACH
mach_port_t
launch_data_get_machport(launch_data_t d)
{
	return d->mp;
}
#endif
