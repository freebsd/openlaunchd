# $FreeBSD$

PROG=liblaunch_test
MAN=

DPADD= ${LIBLAUNCH}
LDADD= ${LIBLAUNCH}

SRCS=liblaunch_test.c cmocka.c launch_getters.c getter_tests.c byteswap_tests.c
CFLAGS+=-I../../support/cmocka/include -I../ -I/usr/local/include

.include "../../launchd.prog.mk"
