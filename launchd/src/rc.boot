#!/bin/sh

##
# Copyright 1997-2002 Apple Computer, Inc.
#
# This script sets up the machine enough to run single-user
##

##
# Set shell to ignore Control-C, etc.
# Prevent inadvertent problems caused by interrupting the shell during boot.
##
stty intr  undef
stty kill  undef
stty quit  undef
stty susp  undef
stty start undef
stty stop  undef
stty dsusp undef

. /etc/rc.common


##
# Arguments
##
BootType=${1-multiuser}


##
# Handle options
##

SafeBoot=""

args=$(/usr/bin/getopt x $*)
set -- ${args};
for option; do
    case "${option}" in
      -x)
        SafeBoot="-x"
	;;
    esac;
done;

##
# Start with some a reasonable hostname
##
hostname localhost

##
# Are we booting from a CD-ROM?  If so, make a note of the fact.
##
if [ -d /System/Installation ] && [ -f /private/etc/rc.cdrom ]; then
    ConsoleMessage "Root device is mounted read-only"
    ConsoleMessage "Filesystem checks skipped"
    iscdrom=1
else
    iscdrom=0
fi

##
# Are we netbooted?
##
netboot=$(/usr/sbin/sysctl kern.netboot | /usr/bin/sed -e 's/^[^0-9]*//')

##
# Output the date for reference.
##
date

##
# Initialize netboot
##
if [ ${iscdrom} -ne 1 -a  "${netboot}" = "1" ] ; then
    ConsoleMessage "Initializing NetBoot"
    if ! sh /etc/rc.netboot start ; then
	echo NetBoot initialization failed, shut down in 10 seconds...
	sleep 10
	echo Shutting down.
	halt
    fi
fi

##
# We must fsck here before we touch anything in the filesystems.
##
fsckerror=0

# Don't fsck if we're single-user, or if we're on a CD-ROM.
if [ ${iscdrom} -ne 1 ]; then
    if [ "${BootType}" = "singleuser" ]; then
	ConsoleMessage "Singleuser boot -- fsck not done"
	ConsoleMessage "Root device is mounted read-only"
	ConsoleMessage "If you want to make modifications to files,"
	ConsoleMessage "run '/sbin/fsck -y' first and then '/sbin/mount -uw /' "
    else
	# We're neither single-user nor on a CD-ROM.
	# Erase the rom's old-style login panel
	ConsoleMessage "Checking disk"

	# Benignly clean up ("preen") any dirty filesystems. 
	# fsck -p will skip disks which were properly unmounted during
	# a normal shutdown.
	# fsck always runs during SafeBoot
	if [ "${SafeBoot}" = "-x" ]; then
	    fsck -fy
	else
	    fsck -p
	fi

	# fsck's success is reflected in its status.
	case $? in
	  0)
	    # No problems
	    ;;
	  2) 
	    # Request was made (via SIGQUIT, ^\) to complete fsck
	    # but prevent going multi-user.
	    ConsoleMessage "Request to remain single-user received"
	    fsckerror=1
	    ;;
	  4)
	    # The root filesystem was checked and fixed.  Let's reboot.
	    # Note that we do NOT sync the disks before rebooting, to
	    # ensure that the filesystem versions of everything fsck fixed
	    # are preserved, rather than being overwritten when in-memory
	    # buffers are flushed.
	    ConsoleMessage "Root filesystem fixed - rebooting"
	    reboot -q -n
	    ;;
	  8)
	    # Serious problem was found.
	    ConsoleMessage "Reboot failed - serious errors"
	    fsckerror=1
	    ;;
	  12)
	    # fsck was interrupted by SIGINT (^C)
	    ConsoleMessage "Reboot interrupted"
	    fsckerror=1
	    ;;
	  *)
	    # Some other error condition ocurred.
	    ConsoleMessage "Unknown error while checking disks"
	    fsckerror=1
	    ;;
	esac
    fi
fi

##
# Try fsck -y and reboot if the above fails horribly.
# This may create a neverending cycle if your root disk is unrecoverably
#  frobbed, and the only recourse them is to power down or boot single
#  user and hope you know what you're doing.
##
if [ ${fsckerror} -ne 0 ]; then
    fsck -y && reboot
fi

##
# Exit
##
exit 0
