AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -F/System/Library/Frameworks/ApplicationServices.framework/Frameworks -Wall -W -Wshadow -Wsign-compare -DkBootImagePath="\"/System/Library/CoreServices/SystemStarter/QuartzDisplay.bundle/Resources/BootPanel.pdf\""  -DkServerBootImagePath="\"/System/Library/CoreServices/SystemStarter/QuartzDisplay.bundle/Resources/ServerBootPanel.pdf\""

noinst_PROGRAMS = QuartzDisplay

QuartzDisplay_LDFLAGS = -bundle -Wl,-client_name,QuartzDisplay -bundle_loader ../SystemStarter -framework CoreFoundation -framework CoreGraphics

QuartzDisplay_SOURCES = QuartzProgressBar.c QuartzProgressBarData.c QuartzDisplay.c

install-exec-hook:
	mkdir -p $(DESTDIR)/System/Library/CoreServices/SystemStarter/QuartzDisplay.bundle/Resources
	strip -S QuartzDisplay
	cp QuartzDisplay $(DESTDIR)/System/Library/CoreServices/SystemStarter/QuartzDisplay.bundle

install-data-hook:
	cp $(srcdir)/BootPanel.pdf $(DESTDIR)/System/Library/CoreServices/SystemStarter/QuartzDisplay.bundle/Resources
	cp $(srcdir)/ServerBootPanel.pdf $(DESTDIR)/System/Library/CoreServices/SystemStarter/QuartzDisplay.bundle/Resources
