AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -Wall -W -Wshadow -Wsign-compare -I$(srcdir)/..

noinst_PROGRAMS = SafeBootResources

SafeBootResources_LDFLAGS = -bundle -Wl,-client_name,SafeBootResources -bundle_loader ../SystemStarter -framework CoreFoundation -framework Bom

SafeBootResources_SOURCES = SafeBootPrivate.c

install-exec-hook:
	mkdir -p $(DESTDIR)/System/Library/CoreServices/SystemStarter/SafeBootResources.bundle
	strip -S SafeBootResources
	cp SafeBootResources $(DESTDIR)/System/Library/CoreServices/SystemStarter/SafeBootResources.bundle
