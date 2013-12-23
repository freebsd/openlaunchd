# $FreeBSD$

PROG=liblaunch_test
MAN=

DPADD= ${LIBLAUNCH}
LDADD= ${LIBLAUNCH}

LIBLAUNCH_SRCS=liblaunch.c launch_data.c launch_getters.c
CMOCKA_SRCS=cmocka.c
TEST_SRCS=liblaunch_test.c getter_tests.c byteswap_tests.c

SRCS=${TEST_SRCS} ${CMOCKA_SRCS} ${LIBLAUNCH_SRCS}

CFLAGS+=-DUNIT_TEST \
		-I../../support/cmocka/include \
		-I../ \
		-I../../launchd \
		-I/usr/local/include \
		-DDEBUG

.include "../../launchd.prog.mk"
