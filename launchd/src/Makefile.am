AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -Wall -Wextra -Waggregate-return -Wshadow -Wmissing-prototypes -Wmissing-declarations -Werror -D__MigTypeCheck=1

CLEANFILES = bootstrap.h bootstrapServer.c bootstrapUser.c bootstrapServer.h					\
	     launchd_internal.h launchd_internalServer.h launchd_internalServer.h launchd_internalUser.c	\
	     notifyServer.c notifyServer.h job_replyUser.c job_reply.h 

bootstrap.h bootstrapServer.c bootstrapUser.c bootstrapServer.h: $(srcdir)/protocol_legacy.defs
	mig $(MIGFLAGS) -sheader bootstrapServer.h $(srcdir)/protocol_legacy.defs

if LIBS_ONLY

noinst_LIBRARIES = liblaunch.a liblaunch_profile.a

liblaunch_a_SOURCES = liblaunch.c bootstrap_public.c

liblaunch_profile_a_CFLAGS = -pg $(AM_CFLAGS)
liblaunch_profile_a_SOURCES = liblaunch.c bootstrap_public.c

$(srcdir)/bootstrap_public.c:: bootstrap.h

install-data-hook:
	mkdir -p $(DESTDIR)/usr/local/lib/system
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system/liblaunch_debug.a
	cp liblaunch_profile.a $(DESTDIR)/usr/local/lib/system/liblaunch_profile.a

else

sbin_SCRIPTS = service

bin_PROGRAMS = launchctl wait4path
sbin_PROGRAMS = launchd SystemStarter
libexec_PROGRAMS = launchproxy

sysconf_DATA = hostconfig rc.common rc.netboot rc.shutdown

launchctl_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden -I/System/Library/Frameworks/System.framework/PrivateHeaders
launchctl_LDFLAGS = -framework CoreFoundation -weak_library /usr/lib/libedit.dylib

SystemStarter_CFLAGS = -mdynamic-no-pic $(AM_CFLAGS) -fvisibility=hidden
SystemStarter_LDFLAGS = -framework CoreFoundation
SystemStarter_SOURCES = StartupItems.c IPC.c SystemStarter.c

launchd_CFLAGS = -mdynamic-no-pic $(AM_CFLAGS) -Wno-unused-parameter -fvisibility=hidden
launchd_LDFLAGS = -lbsm
launchd_SOURCES = launchd.c launchd_core_logic.c launchd_unix_ipc.c init.c bootstrapServer.c notifyServer.c launchd_internalUser.c launchd_internalServer.c job_replyUser.c launchd_runtime.c

launchd_runtime.c:: notifyServer.h launchd_internal.h
launchd_core_logic.c:: bootstrap.h job_reply.h bootstrap.h bootstrapServer.h

launchproxy_LDFLAGS = -weak_framework Security

notifyServer.c notifyServer.h: /usr/include/mach/notify.defs
	mig $(MIGFLAGS) -header /dev/null -user /dev/null -sheader notifyServer.h /usr/include/mach/notify.defs

job_replyUser.c job_reply.h: $(srcdir)/protocol_job_reply.defs
	mig $(MIGFLAGS) -sheader /dev/null -server /dev/null $(srcdir)/protocol_job_reply.defs

launchd_internal.h launchd_internalServer.c launchd_internalUser.c launchd_internalServer.h: $(srcdir)/launchd_internal.defs
	mig $(MIGFLAGS) -sheader launchd_internalServer.h $(srcdir)/launchd_internal.defs


man1_MANS = wait4path.1 launchctl.1

man5_MANS = launchd.plist.5 launchd.conf.5

man8_MANS = StartupItemContext.8 SystemStarter.8 rc.8 launchd.8 service.8 launchproxy.8

STARTUPITEMS = $(basename $(notdir $(wildcard $(srcdir)/StartupItems/*.plist)))

$(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS)):
	mkdir -p $@
	cp $(srcdir)/StartupItems/$(notdir $@) $@
	chmod 755 $@/$(notdir $@)
	cp $(srcdir)/StartupItems/$(notdir $@).plist $@/StartupParameters.plist

install-startupitems: $(addprefix $(DESTDIR)/System/Library/StartupItems/, $(STARTUPITEMS))

install-data-hook: install-startupitems
	mkdir -p $(DESTDIR)/usr/libexec
	cp $(srcdir)/StartupItemContext $(DESTDIR)/usr/libexec
	mkdir -p $(DESTDIR)/usr/include/servers
	cp $(srcdir)/launch.h $(DESTDIR)/usr/include
	cp $(srcdir)/bootstrap_public.h $(DESTDIR)/usr/include/servers/bootstrap.h
	cp $(srcdir)/bootstrap_public.h $(DESTDIR)/usr/include/servers/bootstrap_defs.h
	mkdir -p $(DESTDIR)/usr/local/include
	cp $(srcdir)/launch_priv.h $(DESTDIR)/usr/local/include
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_user.d
	mkdir -p $(DESTDIR)/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/Library/LaunchAgents
	mkdir -p $(DESTDIR)/System/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/System/Library/LaunchAgents

endif
