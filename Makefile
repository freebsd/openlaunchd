Project	= initng
Extra_Configure_Flags = --sbindir=/sbin --bindir=/bin --sysconfdir=/private/etc
GnuAfterInstall = initng_after_install
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)

initng_after_install::
	mkdir -p $(DSTROOT)/private/etc/xinetd.d
	chmod 755 $(DSTROOT)/private/etc/xinetd.d
	install -m 644 xinetd.d/* $(DSTROOT)/private/etc/xinetd.d
