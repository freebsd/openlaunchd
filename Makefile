Project	= initng
Extra_Configure_Flags = --sbindir=/sbin --sysconfdir=/private/etc
GnuAfterInstall = initng_after_install
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)

initng_after_install::
	rm -rf $(DSTROOT)/private
	rm -rf $(DSTROOT)/usr
	rm -rf $(DSTROOT)/System
