# Open Launchd

Mac OS X 10.4 Tiger introduced a new program called `launchd`. The daemon
replaced `SystemStarter` (MacOS legacy) and older `rc.d` (BSD legacy) startup
processes and job management functionality.

Launchd can be split into two logical pieces, "process 1", i.e. the root
launchd which controls system startup and system daemons and "user launchd"
which allows invividual users to manage their own processes/jobs.


## Why?

The primary goal of this project is to port `launchd` in its entirety over to
FreeBSD, hopefully making it usable by other BSD or Linux systems along the
way. That said, the primary motivator for the original porting work in 2005 was
to improve boot time. While improved boot time would be of tangible benefit to
FreeBSD users, the current motivator of this project is to enable **modern
process management for user and system level processes** on FreeBSD systems.


## Resources

 * `#openlaunchd` on the [Freenode](http://freenode.net) is where development
   discussion can occur.
 * The main project [home page](https://wiki.freebsd.org/launchd) can be found
   on the FreeBSD [project wiki](https://wiki.freebsd.org/).
 * `rwatson@` runs [fxr.watson.org](http://fxr.watson.org/) which can be very
   useful for cross-referencing Apple system headers and code, with FreeBSD system
   headers and code
