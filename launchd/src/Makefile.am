AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -Wall -W -Wshadow -Wsign-compare

sbin_SCRIPTS = service

noinst_LIBRARIES = liblaunch.a

bin_PROGRAMS = launchctl wait4path

sbin_PROGRAMS = launchd SystemStarter mach_init launchdebugd

libexec_PROGRAMS = ConsoleMessage register_mach_bootstrap_servers StartupItemContext launchproxy

sysconf_DATA = hostconfig rc rc.common rc.netboot rc.shutdown

SystemStarter_LDFLAGS = -framework CoreFoundation

ConsoleMessage_LDFLAGS = -framework CoreFoundation

launchctl_LDFLAGS = -framework CoreFoundation liblaunch.1.dylib

launchd_LDFLAGS = liblaunch.1.dylib

launchdebugd_LDFLAGS = liblaunch.1.dylib

launchproxy_LDFLAGS = liblaunch.1.dylib

liblaunch_a_SOURCES = liblaunch.c

register_mach_bootstrap_servers_LDFLAGS = -framework CoreFoundation

SystemStarter_SOURCES = StartupItems.c IPC.c SystemStarter.c

launchd_SOURCES = launchd.c init.c bootstrap.c lists.c rpc_services.c bootstrapServer.c

mach_init_SOURCES = mach_init.c bootstrap.c lists.c rpc_services.c bootstrapServer.c

CLEANFILES = bootstrap.h bootstrapServer.c bootstrapUser.c liblaunch.1.dylib

bootstrap.c:: bootstrap.h

bootstrap.h bootstrapServer.c bootstrapUser.c: $(srcdir)/bootstrap.defs
	mig $(MIGFLAGS) $(srcdir)/bootstrap.defs

liblaunch.1.dylib: liblaunch.o
	libtool -dynamic -o liblaunch.1.dylib -install_name /usr/lib/liblaunch.1.dylib -compatibility_version 1 -current_version 1 liblaunch.o -lSystem

launchctl.c:: liblaunch.1.dylib

launchdebugd.c:: liblaunch.1.dylib

launchd.c:: liblaunch.1.dylib

launchproxy.c:: liblaunch.1.dylib

man1_MANS = wait4path.1 launchctl.1

man5_MANS = launchd.conf.5

man8_MANS = ConsoleMessage.8 StartupItemContext.8 SystemStarter.8 init.8 mach_init.8 rc.8 launchd.8 service.8

STARTUPITEMS = $(basename $(notdir $(wildcard $(srcdir)/StartupItems/*.plist)))

$(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS)):
	mkdir -p $@
	cp $(srcdir)/StartupItems/$(notdir $@) $@
	chmod 755 $@/$(notdir $@)
	cp $(srcdir)/StartupItems/$(notdir $@).plist $@/StartupParameters.plist

install-startupitems: $(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS))

install-data-hook: install-startupitems
	mkdir -p $(DESTDIR)/usr/local/lib/system
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system/liblaunch_debug.a
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system/liblaunch_profile.a
	mkdir -p $(DESTDIR)/usr/lib
	strip -S liblaunch.1.dylib
	cp liblaunch.1.dylib $(DESTDIR)/usr/lib
	ln -s liblaunch.1.dylib $(DESTDIR)/usr/lib/liblaunch.dylib
	mkdir -p $(DESTDIR)/usr/include
	cp $(srcdir)/launch.h $(DESTDIR)/usr/include
	mkdir -p $(DESTDIR)/usr/local/include
	cp $(srcdir)/launch_priv.h $(DESTDIR)/usr/local/include
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_user.d
	mkdir -p $(DESTDIR)/System/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/System/Library/LaunchAgents

install-exec-hook:
	chmod u+s $(DESTDIR)/$(sbindir)/launchd
