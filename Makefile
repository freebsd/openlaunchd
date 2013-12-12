# $FreeBSD$

MAINTAINER=tyler@freebsd.org

SUBDIR=liblaunch/test \
	   liblaunch \
	   wait4path \
	   launchproxy \
	   launchctl


test: liblaunch/test wait4path #liblaunch launchproxy
	@./support/roundup ./t/*.sh

.include <bsd.subdir.mk>
