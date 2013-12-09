# $FreeBSD$

MAINTAINER=tyler@freebsd.org

SUBDIR=liblaunch/test \
	   liblaunch \
	   wait4path \
	   launchproxy \
	   launchctl


test: liblaunch wait4path launchproxy
	@./support/roundup ./t/*.sh

.include <bsd.subdir.mk>
