CWARN = -Wall -Wextra -Waggregate-return -Wfloat-equal -Wshadow -Wpacked -Wmissing-prototypes -Wmissing-declarations -Werror # gcc4.2: -Wstrict-overflow=4 # -Wpadded -Wconversion -Wstrict-aliasing=2
CTUNE = -fvisibility=hidden # gcc4.2: -fdiagnostics-show-option # -fstrict-aliasing
CMISC = -isysroot $(SDKROOT) -F$(SDKROOT)/System/Library/PrivateFrameworks -D__MigTypeCheck=1 -Dmig_external=__private_extern__ -D_DARWIN_USE_64_BIT_INODE=1
AM_CFLAGS = $(CTUNE) $(CMISC) $(CWARN)
AM_LDFLAGS = -Wl,-syslibroot,$(SDKROOT)

CLEANFILES = protocol_vproc.h protocol_vprocServer.c protocol_vprocUser.c protocol_vprocServer.h		\
	     launchd_internal.h launchd_internalServer.h launchd_internalServer.c launchd_internalUser.c	\
	     notifyServer.c notifyServer.h job_replyUser.c job_reply.h __version.c mach_excServer.c mach_excServer.h

protocol_vproc.h protocol_vprocServer.c protocol_vprocUser.c protocol_vprocServer.h: $(srcdir)/protocol_job.defs
	mig $(MIGFLAGS) -sheader protocol_vprocServer.h $(srcdir)/protocol_job.defs

if LIBS_ONLY

noinst_LIBRARIES = liblaunch.a liblaunch_profile.a

liblaunch_a_CFLAGS = -D__DARWIN_NON_CANCELABLE=1 $(AM_CFLAGS)
liblaunch_a_SOURCES = liblaunch.c libvproc.c libbootstrap.c protocol_vprocUser.c __version.c

liblaunch_profile_a_CFLAGS = -pg -D__DARWIN_NON_CANCELABLE=1 $(AM_CFLAGS)
liblaunch_profile_a_SOURCES = liblaunch.c libvproc.c libbootstrap.c protocol_vprocUser.c __version.c

$(srcdir)/libvproc.c:: protocol_vproc.h

$(srcdir)/protocol_vprocUser.c:: protocol_vproc.h

__version.c:
	/Developer/Makefiles/bin/version.pl launchd_libs > $@


install-data-hook:
	mkdir -p $(DESTDIR)/usr/local/lib/system
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system
	cp liblaunch.a $(DESTDIR)/usr/local/lib/system/liblaunch_debug.a
	cp liblaunch_profile.a $(DESTDIR)/usr/local/lib/system/liblaunch_profile.a

else

bin_PROGRAMS = launchctl wait4path
if DO_EMBEDDED_MAGIC
sbin_PROGRAMS = launchd
else
sbin_PROGRAMS = launchd SystemStarter
endif
libexec_PROGRAMS = launchproxy

sysconf_DATA = hostconfig rc.common rc.netboot

launchctl_CFLAGS = $(AM_CFLAGS) -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
launchctl_LDFLAGS = $(AM_LDFLAGS) -framework CoreFoundation -framework IOKit $(LIBS_SECURITY) -weak_library /usr/lib/libedit.dylib

if DO_EMBEDDED_MAGIC
else
SystemStarter_CFLAGS = -mdynamic-no-pic $(AM_CFLAGS)
SystemStarter_LDFLAGS = $(AM_LDFLAGS) -framework CoreFoundation -framework IOKit
SystemStarter_SOURCES = StartupItems.c IPC.c SystemStarter.c
endif

launchd_CFLAGS = -mdynamic-no-pic $(AM_CFLAGS) -freorder-blocks
launchd_LDFLAGS = $(AM_LDFLAGS) -lbsm
launchd_SOURCES = launchd.c launchd_core_logic.c launchd_unix_ipc.c protocol_vprocServer.c notifyServer.c launchd_internalUser.c launchd_internalServer.c job_replyUser.c launchd_runtime.c launchd_runtime_kill.c job_forwardUser.c mach_excServer.c

launchd_runtime.c:: notifyServer.h launchd_internal.h mach_excServer.h
launchd_core_logic.c:: protocol_vproc.h job_reply.h protocol_vprocServer.h job_forward.h

launchproxy_LDFLAGS = $(AM_LDFLAGS) $(LIBS_SECURITY)

job_forwardUser.c job_forward.h: $(srcdir)/protocol_job_forward.defs
	mig $(MIGFLAGS) -sheader /dev/null -server /dev/null $(srcdir)/protocol_job_forward.defs

notifyServer.c notifyServer.h: /usr/include/mach/notify.defs
	mig $(MIGFLAGS) -header /dev/null -user /dev/null -sheader notifyServer.h /usr/include/mach/notify.defs

mach_excServer.c mach_excServer.h: /usr/include/mach/mach_exc.defs
	mig $(MIGFLAGS) -header /dev/null -user /dev/null -sheader mach_excServer.h /usr/include/mach/mach_exc.defs

job_replyUser.c job_reply.h: $(srcdir)/protocol_job_reply.defs
	mig $(MIGFLAGS) -sheader /dev/null -server /dev/null $(srcdir)/protocol_job_reply.defs

launchd_internal.h launchd_internalServer.c launchd_internalUser.c launchd_internalServer.h: $(srcdir)/launchd_internal.defs
	mig $(MIGFLAGS) -sheader launchd_internalServer.h $(srcdir)/launchd_internal.defs


man1_MANS = wait4path.1 launchctl.1

man5_MANS = launchd.plist.5 launchd.conf.5

if DO_EMBEDDED_MAGIC
man8_MANS = launchd.8 launchproxy.8
else
man8_MANS = StartupItemContext.8 SystemStarter.8 rc.8 launchd.8 launchproxy.8
endif

install-data-hook:
	mkdir -p $(DESTDIR)/usr/libexec
	mkdir -p $(DESTDIR)/usr/include/servers
	mkdir -p $(DESTDIR)/usr/local/include
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_user.d
	mkdir -p $(DESTDIR)/$(sysconfdir)/mach_init_per_login_session.d
	mkdir -p $(DESTDIR)/Library/LaunchDaemons
	mkdir -p $(DESTDIR)/Library/LaunchAgents
	mkdir -p $(DESTDIR)/System/Library/LaunchAgents
	mkdir -p $(DESTDIR)/System/Library/LaunchDaemons
	cp $(srcdir)/liblaunch_public.h $(DESTDIR)/usr/include/launch.h
	cp $(srcdir)/libvproc_public.h $(DESTDIR)/usr/include/vproc.h
	cp $(srcdir)/libbootstrap_public.h $(DESTDIR)/usr/include/servers/bootstrap.h
	cp $(srcdir)/libbootstrap_public.h $(DESTDIR)/usr/include/servers/bootstrap_defs.h
	cp $(srcdir)/libbootstrap_private.h $(DESTDIR)/usr/local/include/bootstrap_priv.h
	cp $(srcdir)/liblaunch_private.h $(DESTDIR)/usr/local/include/launch_priv.h
	cp $(srcdir)/libvproc_private.h $(DESTDIR)/usr/local/include/vproc_priv.h
	cp $(srcdir)/reboot2.h $(DESTDIR)/usr/local/include/reboot2.h
if DO_EMBEDDED_MAGIC
else
	cp $(srcdir)/StartupItemContext $(DESTDIR)/usr/libexec
	cp $(srcdir)/com.apple.SystemStarter.plist $(DESTDIR)/System/Library/LaunchDaemons
endif

endif
