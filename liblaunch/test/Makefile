# $FreeBSD$

PROG=liblaunch_test
MAN=

DPADD= ${LIBLAUNCH}
LDADD= ${LIBLAUNCH}

SRCS=liblaunch_test.c cmocka.c
CFLAGS+=-I../../support/cmocka/include -I../

.include "../../launchd.prog.mk"
