# $FreeBSD$

PROG=liblaunch_test
MAN=

DPADD= ${LIBLAUNCH}
LDADD= ${LIBLAUNCH}

SRCS=liblaunch_test.c cmocka.c launch_getters.c liblaunch.c getter_tests.c byteswap_tests.c
CFLAGS+=-DUNIT_TEST \
		-I../../support/cmocka/include \
		-I../ \
		-I../../launchd \
		-I/usr/local/include \
		-DDEBUG

.include "../../launchd.prog.mk"
