SUBDIRS = . QuartzDisplay SafeBoot SystemStarterResources

AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -Wall -W -Wshadow -Wsign-compare

sbin_SCRIPTS = service

noinst_LIBRARIES = liblaunch.a

bin_PROGRAMS = launchctl wait4path

sbin_PROGRAMS = launchd SystemStarter init mach_init launchdebugd

libexec_PROGRAMS = ConsoleMessage register_mach_bootstrap_servers StartupItemContext launchproxy

sysconf_DATA = hostconfig rc rc.boot rc.cleanup rc.common rc.netboot

SystemStarter_LDFLAGS = -framework CoreFoundation

ConsoleMessage_LDFLAGS = -framework CoreFoundation

launchctl_LDFLAGS = -framework CoreFoundation liblaunch.1.dylib

launchd_LDFLAGS = liblaunch.1.dylib

launchdebugd_LDFLAGS = liblaunch.1.dylib

launchproxy_LDFLAGS = liblaunch.1.dylib

register_mach_bootstrap_servers_LDFLAGS = -framework CoreFoundation

SystemStarter_SOURCES = StartupItems.c IPC.c SystemStarter.c \
	Log.c TextDisplay.c main.c SafeBoot.c

wait4path_SOURCES = wait4path.c

init_SOURCES = init.c

liblaunch_a_SOURCES = liblaunch.c

launchdebugd_SOURCES = launchdebugd.c

launchctl_SOURCES = launchctl.c

launchd_SOURCES = launchd.c

launchproxy_SOURCES = launchproxy.c

mach_init_SOURCES = bootstrap.c lists.c error_log.c rpc_services.c bootstrapServer.c

CLEANFILES = bootstrap.h bootstrapServer.c bootstrapUser.c liblaunch.1.dylib

bootstrap.c:: bootstrap.h

bootstrap.h bootstrapServer.c bootstrapUser.c: $(srcdir)/bootstrap.defs
	mig $(MIGFLAGS) $(srcdir)/bootstrap.defs

liblaunch.1.dylib:
	libtool -dynamic -o liblaunch.1.dylib -install_name /usr/lib/liblaunch.1.dylib -compatibility_version 1 -current_version 1 liblaunch.o -lSystem

launchctl.c:: liblaunch.1.dylib

launchdebugd.c:: liblaunch.1.dylib

launchd.c:: liblaunch.1.dylib

launchproxy.c:: liblaunch.1.dylib

man1_MANS = wait4path.1

man8_MANS = ConsoleMessage.8 StartupItemContext.8 SystemStarter.8 init.8 mach_init.8

STARTUPITEMS = $(basename $(notdir $(wildcard $(srcdir)/StartupItems/*.plist)))

$(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS)):
	mkdir -p $@/Resources/English.lproj
	cp $(srcdir)/StartupItems/$(notdir $@) $@
	chmod 755 $@/$(notdir $@)
	cp $(srcdir)/StartupItems/$(notdir $@).plist $@/StartupParameters.plist
	cp $(srcdir)/StartupItems/$(notdir $@).strings $@/Resources/English.lproj/Localizable.strings

install-startupitems: $(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS))

install-data-hook: install-startupitems
	mkdir -p $(DESTDIR)/usr/lib
	strip -S liblaunch.1.dylib
	cp liblaunch.1.dylib $(DESTDIR)/usr/lib
	ln -s liblaunch.1.dylib $(DESTDIR)/usr/lib/liblaunch.dylib
	mkdir -p $(DESTDIR)/usr/include
	cp $(srcdir)/launch.h $(DESTDIR)/usr/include
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_user.d
	mkdir -p $(DESTDIR)/System/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/System/Library/LaunchAgents
