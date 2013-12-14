/*
 * Copyright (c) 2013 Apple, Inc., R. Tyler Croy, All rights reserved.
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

#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#define host2wire(x)				\
	({ typeof (x) _X, _x = (x);		\
	 switch (sizeof(_x)) {			\
	 case 8:				\
	 	_X = htobe64(_x); \
	 	break;				\
	 case 4:				\
	 	_X = htobe32(_x); \
	 	break;				\
	 case 2:				\
	 	_X = htobe16(_x); \
	 	break;				\
	 case 1:				\
	 	_X = _x; \
		break;				\
	 default:				\
	 	_X = x; \
		break;				\
	 }					\
	 _X;					\
	 })

#define wire2host(x)				\
	({ typeof (x) _X, _x = (x);		\
	 switch (sizeof(_x)) {			\
	 case 8:				\
	 	_X = be64toh(_x); \
	 	break;				\
	 case 4:				\
        _X = be32toh(_x); \
	 	break;				\
	 case 2:				\
	 	_X = be16toh(_x); \
	 	break;				\
	 case 1:				\
	 	_X = _x;			\
		break;				\
	 default:				\
	 	_X = _x; \
		break;				\
	 }					\
	 _X;					\
	 })


union _launch_double_u {
	uint64_t iv;
	double dv;
};

#define host2wire_f(x) ({ \
	typeof(x) _F, _f = (x); \
	union _launch_double_u s; \
	s.dv = _f; \
	s.iv = host2wire(s.iv); \
	_F = s.dv; \
	_F; \
})

#define wire2host_f(x) ({ \
	typeof(x) _F, _f = (x); \
	union _launch_double_u s; \
	s.dv = _f; \
	s.iv = wire2host(s.iv); \
	_F = s.dv; \
	_F; \
})
