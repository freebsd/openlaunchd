ifndef SDKROOT
export SDKROOT = /
endif

Project	= launchd
Extra_Configure_Flags = --sbindir=/sbin --bindir=/bin --sysconfdir=/private/etc
GnuAfterInstall = launchd_after_install
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)

ifeq ($(shell tconf --test TARGET_OS_EMBEDDED),YES)
Extra_Configure_Flags += --host=none-apple-darwin
endif

launchd_after_install::
ifeq ($(RC_ProjectName),launchd_libs)
	-find -d $(DSTROOT) -type f | grep -v /usr/local/lib/system | xargs rm
	-find -d $(DSTROOT) -type l | grep -v /usr/local/lib/system | xargs rm
	-find -d $(DSTROOT) -type d | grep -v /usr/local/lib/system | xargs rmdir
else
ifeq ($(shell tconf --test TARGET_OS_EMBEDDED),NO)
	mkdir -p $(DSTROOT)/Library/StartupItems
	chmod 755 $(DSTROOT)/Library/StartupItems
	mkdir -p $(DSTROOT)/System/Library/StartupItems
	chmod 755 $(DSTROOT)/System/Library/StartupItems
endif
	rm -rf $(DSTROOT)/usr/local/lib/system
	cp $(OBJROOT)/src/launchd $(SYMROOT)
	cp $(OBJROOT)/src/launchctl $(SYMROOT)
	cp $(OBJROOT)/src/launchproxy $(SYMROOT)
	-dsymutil $(SYMROOT)/launchd
	-dsymutil $(SYMROOT)/launchctl
	-dsymutil $(SYMROOT)/launchproxy
endif

launchd_libs:: install
