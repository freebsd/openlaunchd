# $FreeBSD$

MAINTAINER=tyler@freebsd.org

SUBDIR=liblaunch/test \
	   liblaunch \
	   wait4path \
	   launchproxy \
	   launchctl \
	   launchd


test: liblaunch/test wait4path liblaunch
	@for d in `find . -iname "*_test"`; do \
		echo "> Running $$d" && ./$$d ; \
	done

	@./support/roundup ./t/*.sh

docs:
	doxygen launchd.doxy

.include <bsd.subdir.mk>
