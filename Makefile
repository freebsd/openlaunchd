# $FreeBSD$

MAINTAINER=tyler@freebsd.org

SUBDIR=wait4path \
	   launchproxy \
	   launchctl


test: wait4path launchproxy
	@./support/roundup ./t/*.sh

.include <bsd.subdir.mk>
