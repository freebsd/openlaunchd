# $FreeBSD$

MAINTAINER=tyler@freebsd.org

SUBDIR=liblaunch/test \
	   liblaunch \
	   wait4path \
	   launchproxy \
	   launchctl


test: liblaunch/test wait4path #liblaunch launchproxy
	@for d in `find . -iname "*_test"`; do \
		echo "> Running $$d" && ./$$d ; \
	done

	@./support/roundup ./t/*.sh

.include <bsd.subdir.mk>
