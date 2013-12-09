# $FreeBSD$

PROG=liblaunch_test
MAN=

DPADD= ${LIBLAUNCH}
LDADD= ${LIBLAUNCH}

SRCS=liblaunch_test.c cmocka.c
CFLAGS+=-I../../support/cmocka/include

.include "../../launchd.prog.mk"
