# $FreeBSD$

MAINTAINER=tyler@freebsd.org

CFLAGS+=-g -I${PWD}/../launchd \
		-I${PWD}/../liblaunch \
		-I/usr/local/include \
		-DDEBUG

.include <bsd.prog.mk>
