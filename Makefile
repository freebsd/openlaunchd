Project	= launchd
Extra_Configure_Flags = --sbindir=/sbin --bindir=/bin --sysconfdir=/private/etc
GnuAfterInstall = launchd_after_install
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)

launchd_after_install::
	mkdir -p $(DSTROOT)/private/etc/xinetd.d
	chmod 755 $(DSTROOT)/private/etc/xinetd.d
	install -m 644 xinetd.d/* $(DSTROOT)/private/etc/xinetd.d
	mkdir -p $(DSTROOT)/System/Library/LaunchDaemons
	chmod 755 $(DSTROOT)/System/Library/LaunchDaemons
	install -m 644 LaunchDaemons/* $(DSTROOT)/System/Library/LaunchDaemons
