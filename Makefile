Project	= launchd
Extra_Configure_Flags = --sbindir=/sbin --bindir=/bin --sysconfdir=/private/etc
GnuAfterInstall = launchd_after_install
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)

launchd_after_install::
ifeq ($(RC_ProjectName),launchd_libs)
	-find -d $(DSTROOT) -type f | grep -v /usr/local/lib/system | xargs rm
	-find -d $(DSTROOT) -type l | grep -v /usr/local/lib/system | xargs rm
	-find -d $(DSTROOT) -type d | grep -v /usr/local/lib/system | xargs rmdir
else
	mkdir -p $(DSTROOT)/Library/StartupItems
	chmod 755 $(DSTROOT)/Library/StartupItems
	mkdir -p $(DSTROOT)/private/etc/xinetd.d
	chmod 755 $(DSTROOT)/private/etc/xinetd.d
	install -m 644 xinetd.d/* $(DSTROOT)/private/etc/xinetd.d
	mkdir -p $(DSTROOT)/System/Library/LaunchDaemons
	chmod 755 $(DSTROOT)/System/Library/LaunchDaemons
	install -m 644 LaunchDaemons/* $(DSTROOT)/System/Library/LaunchDaemons
	rm -rf $(DSTROOT)/usr/local/lib/system
	mkdir -p $(DSTROOT)/usr/sbin
	mv $(DSTROOT)/sbin/launchd_helperd $(DSTROOT)/usr/sbin
endif

launchd_libs:: install
