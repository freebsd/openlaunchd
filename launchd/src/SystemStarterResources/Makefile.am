WHERE=/System/Library/CoreServices/SystemStarter/SystemStarterResources.bundle/Resources/English.lproj

install-data-hook:
	mkdir -p $(DESTDIR)/$(WHERE)
	cp $(srcdir)/InfoPlist.strings $(DESTDIR)/$(WHERE)
	cp $(srcdir)/Localizable.strings $(DESTDIR)/$(WHERE)
