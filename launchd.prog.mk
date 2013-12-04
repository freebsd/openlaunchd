# $FreeBSD$


CFLAGS+=-Werror -I${PWD}/../src -I${PWD}/../liblaunch

.include <bsd.prog.mk>
