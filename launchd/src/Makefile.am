AM_CFLAGS = -no-cpp-precomp -F/System/Library/PrivateFrameworks -Wall -Wextra -Waggregate-return -Wshadow -Wmissing-prototypes -Wmissing-declarations -Werror -D__MigTypeCheck=1 -fvisibility=hidden -Dmig_external=__private_extern__

CLEANFILES = protocol_vproc.h protocol_vprocServer.c protocol_vprocUser.c protocol_vprocServer.h		\
	     launchd_internal.h launchd_internalServer.h launchd_internalServer.c launchd_internalUser.c	\
	     notifyServer.c notifyServer.h job_replyUser.c job_reply.h 

protocol_vproc.h protocol_vprocServer.c protocol_vprocUser.c protocol_vprocServer.h: $(srcdir)/protocol_job.defs
	mig $(MIGFLAGS) -sheader protocol_vprocServer.h $(srcdir)/protocol_job.defs

if LIBS_ONLY

noinst_LIBRARIES = liblaunch.a liblaunch_profile.a

liblaunch_a_SOURCES = liblaunch.c libvproc.c libbootstrap.c protocol_vprocUser.c

liblaunch_profile_a_CFLAGS = -pg $(AM_CFLAGS)
liblaunch_profile_a_SOURCES = liblaunch.c libvproc.c libbootstrap.c protocol_vprocUser.c

$(srcdir)/libvproc.c:: protocol_vproc.h

$(srcdir)/protocol_vprocUser.c:: protocol_vproc.h

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

launchctl_CFLAGS = $(AM_CFLAGS) -I/System/Library/Frameworks/System.framework/PrivateHeaders
launchctl_LDFLAGS = -framework CoreFoundation -weak_library /usr/lib/libedit.dylib

SystemStarter_CFLAGS = -mdynamic-no-pic $(AM_CFLAGS)
SystemStarter_LDFLAGS = -framework CoreFoundation
SystemStarter_SOURCES = StartupItems.c IPC.c SystemStarter.c

launchd_CFLAGS = -mdynamic-no-pic $(AM_CFLAGS) -Wno-unused-parameter
launchd_LDFLAGS = -lbsm
launchd_SOURCES = launchd.c launchd_core_logic.c launchd_unix_ipc.c init.c protocol_vprocServer.c notifyServer.c launchd_internalUser.c launchd_internalServer.c job_replyUser.c launchd_runtime.c

launchd_runtime.c:: notifyServer.h launchd_internal.h
launchd_core_logic.c:: protocol_vproc.h job_reply.h protocol_vprocServer.h

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
	cp $(srcdir)/liblaunch_public.h $(DESTDIR)/usr/include/launch.h
	cp $(srcdir)/libvproc_public.h $(DESTDIR)/usr/include/vproc.h
	cp $(srcdir)/libbootstrap_public.h $(DESTDIR)/usr/include/servers/bootstrap.h
	cp $(srcdir)/libbootstrap_public.h $(DESTDIR)/usr/include/servers/bootstrap_defs.h
	mkdir -p $(DESTDIR)/usr/local/include
	cp $(srcdir)/liblaunch_private.h $(DESTDIR)/usr/local/include/launch_priv.h
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_user.d
	mkdir -p $(DESTDIR)/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/Library/LaunchAgents
	mkdir -p $(DESTDIR)/System/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/System/Library/LaunchAgents

endif
