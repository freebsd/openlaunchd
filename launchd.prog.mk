# $FreeBSD$


CFLAGS+=-g -I${PWD}/../src \
		-I${PWD}/../liblaunch \
		-I/usr/local/include

.include <bsd.prog.mk>
