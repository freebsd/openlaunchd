Project	= initng
Extra_Configure_Flags = --sbindir=/sbin --sysconfdir=/private/etc
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/GNUSource.make
Install_Flags = DESTDIR=$(DSTROOT)
