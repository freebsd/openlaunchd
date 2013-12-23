# $FreeBSD$

MAINTAINER=tyler@freebsd.org

LIB=launch
SRCS=liblaunch.c libbootstrap.c libvproc.c launch_getters.c
CFLAGS+=-g -I${PWD}/../launchd \
		-I/usr/local/include \
		-DDEBUG

.include <bsd.lib.mk>

