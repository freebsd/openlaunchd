AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -Wall -W -Wshadow -Wsign-compare

sbin_SCRIPTS = service

sbin_PROGRAMS = initctl initngd wait4path SystemStarter init mach_init

noinst_PROGRAMS = helloworldd

libexec_PROGRAMS = ConsoleMessage register_mach_bootstrap_servers StartupItemContext

sysconf_DATA = hostconfig rc rc.boot rc.cleanup rc.common rc.netboot

SystemStarter_LDFLAGS = -framework CoreFoundation -framework Bom

ConsoleMessage_LDFLAGS = -framework CoreFoundation

initctl_LDFLAGS = -framework CoreFoundation

register_mach_bootstrap_servers_LDFLAGS = -framework CoreFoundation

SystemStarter_SOURCES = StartupItems.c IPC.c SystemStarter.c \
	Log.c TextDisplay.c main.c SafeBootPrivate.c

wait4path_SOURCES = wait4path.c

helloworldd_SOURCES = libinitng.c helloworldd.c

init_SOURCES = init.c

initctl_SOURCES = libinitng.c initctl.c

initngd_SOURCES = libinitng.c initngd.c

mach_init_SOURCES = bootstrap.c lists.c error_log.c rpc_services.c bootstrapServer.c

CLEANFILES = bootstrap.h bootstrapServer.c bootstrapUser.c

bootstrap.c:: bootstrap.h

bootstrap.h bootstrapServer.c bootstrapUser.c:
	mig $(MIGFLAGS) $(srcdir)/bootstrap.defs

man1_MANS = wait4path.1

man8_MANS = ConsoleMessage.8 StartupItemContext.8 SystemStarter.8 init.8 mach_init.8

STARTUPITEMS = $(basename $(notdir $(wildcard $(srcdir)/StartupItems/*.plist)))

$(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS)):
	mkdir -p $@/Resources/English.lproj
	cp $(srcdir)/StartupItems/$(notdir $@) $@
	cp $(srcdir)/StartupItems/$(notdir $@).plist $@/StartupParameters.plist
	cp $(srcdir)/StartupItems/$(notdir $@).strings $@/Resources/English.lproj/Localizable.strings

install-startupitems: $(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS))

install-data-hook: install-startupitems
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_user.d
