# $FreeBSD$


CFLAGS+=-g -I${PWD}/../launchd \
		-I${PWD}/../liblaunch \
		-I/usr/local/include

.include <bsd.prog.mk>
