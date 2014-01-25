# $FreeBSD$

MAINTAINER=tyler@freebsd.org

LIB=launch
SRCS=liblaunch.c libbootstrap.c \
	launch_getters.c \
	launch_data.c # XXX: Disabled, see #5 libvproc.c
CFLAGS+=-g -I${PWD}/../launchd \
		-I/usr/local/include \
		-DDEBUG

.include <bsd.lib.mk>

