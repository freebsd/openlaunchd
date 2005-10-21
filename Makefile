Project	= launchd
Extra_Configure_Flags = --sbindir=/sbin --bindir=/bin --sysconfdir=/private/etc
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)

launchd_libs:: install
