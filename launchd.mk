# $FreeBSD$

MAINTAINER=tyler@freebsd.org

CFLAGS+=-g -fPIC -fno-exceptions -fstack-protector -fvisibility=hidden

# WARNINGS
CFLAGS+=-Wall -Wextra -Wno-unused-parameter \
		-Wno-unused-label -Wformat -Wreturn-type \
		-Wsign-compare -Wmultichar -Winit-self \
		-Wuninitialized -Wno-deprecated -Wformat-security \
		-Werror

# INCLUDES
CFLAGS+=-I${PWD}/../launchd \
		-I${PWD}/../liblaunch \
		-I/usr/local/include

# DEFINES
CFLAGS+=-DDEBUG

.include <bsd.prog.mk>
