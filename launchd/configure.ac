#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)

AC_INIT([launchd],[1.0],[launchd-bug-reports@group.apple.com])
AC_CONFIG_SRCDIR([src/launchd.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_CC_C_O

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h mach/mach.h netdb.h netinet/in.h paths.h stddef.h stdlib.h string.h sys/ioctl.h sys/mount.h sys/param.h sys/socket.h sys/time.h syslog.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MKTIME
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([atexit dup2 gethostname gettimeofday malloc mmap memmove memset mkdir munmap realloc rmdir select setenv socket strcasecmp strchr strdup strerror strrchr strstr strtol])

# check for a Security framework that includes session support
ac_func_search_save_LIBS=$LIBS
LIBS="-framework Security $ac_func_search_save_LIBS"
AC_CHECK_FUNC([SessionCreate],
	      [AC_DEFINE(HAVE_SECURITY, 1, [Define to 1 if you have the Security framework])
	      AC_SUBST(LIBS_SECURITY,"-framework Security")
	      AC_SUBST(WEAKLIBS_SECURITY,"-weak_framework Security")])
LIBS=$ac_func_search_save_LIBS

# check for seatbelt
AC_CHECK_FUNC([sandbox_init],[AC_DEFINE(HAVE_SANDBOX, 1, [Define to 1 if you have the sandbox library])])

# check for quarantine
AC_CHECK_FUNC([_qtn_proc_init_with_data],[AC_DEFINE(HAVE_QUARANTINE, 1, [Define to 1 if you have the quarantine library])])

AC_CONFIG_FILES([Makefile
                 src/Makefile])

AM_CONDITIONAL(LIBS_ONLY, test "$RC_ProjectName" = launchd_libs)
AM_CONDITIONAL(DO_EMBEDDED_MAGIC, test $(tconf --test TARGET_OS_EMBEDDED) = YES)


AC_OUTPUT
