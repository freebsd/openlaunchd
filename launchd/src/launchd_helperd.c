#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <tcl.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "launch.h"

#define LD_EVENT	"launchd_event"
#define LD_EVENT_FLAGS	"launchd_event_flags"

struct watchpathcb {
        TAILQ_ENTRY(watchpathcb) tqe;
	int fd;
	char *path;
	char *_event;
};

struct jobcb {
        TAILQ_ENTRY(jobcb) tqe;
        launch_data_t ldj;
	Tcl_Interp *tcli;
	CFRunLoopTimerRef rlt;
	char *_event;
        TAILQ_HEAD(watchpathcbhead, watchpathcb) wph;
};

static void wpremove(struct watchpathcbhead *wph, struct watchpathcb *wp);

static TAILQ_HEAD(jobcbhead, jobcb) jobs = TAILQ_HEAD_INITIALIZER(jobs);

static void job_add(launch_data_t j);
static struct jobcb *job_find(const char *label);
static void job_remove(struct jobcb *j);
static void job_start(struct jobcb *j);
static void job_stop(struct jobcb *j);
static void job_tcleval(struct jobcb *j);
static void job_cancel_all_callbacks(struct jobcb *j);

static void myCFSocketCallBack(void);
static void tcl_timer_callback(CFRunLoopTimerRef, void *);
static void reload_jobs(void);
static bool on_battery_power(void);
static void sync_callback(void);

static launch_data_t ldself = NULL;
static int kq = 0;
static char *testtcl = NULL;
static double sync_interval = 30;
static double energy_saving_sync_interval = 30;

static int _start_job(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _stop_job(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _callback_interval(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _watch_path(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _cancel_all_callbacks(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _syslog(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _getproperty(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);

int main(int argc, char *argv[])
{
	launch_data_t si = NULL, si2 = NULL;
	CFRunLoopSourceRef sockrlr = NULL;
	CFSocketRef sockr = NULL;
	CFRunLoopTimerRef syncr = NULL;
	struct kevent kev;
	int ch;

	while ((ch = getopt(argc, argv, "T:")) != -1) {
		switch (ch) {
		case 'T':
			testtcl = optarg;
			break;
		case '?':
		default:
			//usage();
			break;
		}
	}

	openlog(getprogname(), LOG_PID|LOG_CONS|(testtcl ? LOG_PERROR : 0), LOG_LAUNCHD);

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR, "kqueue(): %m");
		exit(EXIT_FAILURE);
	}

	EV_SET(&kev, SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "failed to add kevent for SIGHUP: %m");
		exit(EXIT_FAILURE);
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if (testtcl) {
		struct stat sb;
		char *tclcode;
		launch_data_t j = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_t l = launch_data_new_string("com.apple.launchd_helperd.testtcl");
		launch_data_t t;
		int fd;

		errno = 0;
		if (stat(testtcl, &sb) == -1 && errno != ENOENT) {
			fprintf(stderr, "stat(\"%s\"): %s\n", testtcl, strerror(errno));
			exit(EXIT_FAILURE);
		} else if (errno == 0) {
			tclcode = malloc(sb.st_size);
			if ((fd = open(testtcl, O_RDONLY)) == -1) {
				fprintf(stderr, "open(\"%s\"): %s\n", testtcl, strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (read(fd, tclcode, sb.st_size) == -1) {
				fprintf(stderr, "read(\"%s\"): %s\n", testtcl, strerror(errno));
				exit(EXIT_FAILURE);
			}
			close(fd);
		} else {
			tclcode = testtcl;
		}

		t = launch_data_new_string(tclcode);
		if (tclcode != testtcl)
			free(tclcode);

		launch_data_dict_insert(j, l, LAUNCH_JOBKEY_LABEL);
		launch_data_dict_insert(j, t, LAUNCH_JOBKEY_TCL);

		job_add(j);

		launch_data_free(j);
	} else {
		launch_data_t msg = launch_data_new_string(LAUNCH_KEY_CHECKIN);
		EV_SET(&kev, launch_get_fd(), EVFILT_READ, EV_ADD, 0, 0, 0);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_ERR, "kevent(): %m");
			exit(EXIT_FAILURE);
		}

		ldself = launch_msg(msg);
		launch_data_free(msg);

		if (ldself) {
			si = launch_data_dict_lookup(ldself, "FileSystemSyncInterval");
			si2 = launch_data_dict_lookup(ldself, "FileSystemEnergySavingSyncInterval");
		}

		reload_jobs();
	}

	sockr = CFSocketCreateWithNative(kCFAllocatorDefault, kq, kCFSocketReadCallBack, (CFSocketCallBack)myCFSocketCallBack, NULL);
	if (sockr)
		sockrlr = CFSocketCreateRunLoopSource(kCFAllocatorDefault, sockr, 0);
	if (sockrlr)
		CFRunLoopAddSource(CFRunLoopGetCurrent(), sockrlr, kCFRunLoopDefaultMode);
	else
		exit(EXIT_FAILURE);

	if (si) {
		energy_saving_sync_interval = sync_interval = launch_data_get_integer(si);
		if (si2)
			energy_saving_sync_interval = launch_data_get_integer(si2);
		syncr = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, sync_interval, 0, 0, (CFRunLoopTimerCallBack)sync_callback, NULL);
		if (syncr)
			CFRunLoopAddTimer(CFRunLoopGetCurrent(), syncr, kCFRunLoopDefaultMode);
		else
			syslog(LOG_WARNING, "CFRunLoopTimerCreate() failed");
	}

	CFRunLoopRun();

	exit(EXIT_SUCCESS);
}

static void sync_callback(void)
{
	static double last_sync = 0;
	static double current_sync_interval = 0;

	if (on_battery_power())
		current_sync_interval = energy_saving_sync_interval;
	else
		current_sync_interval = sync_interval;

	if (last_sync >= current_sync_interval) {
		sync();
		last_sync = 0;
	} else {
		last_sync += sync_interval;
	}
}

static void reload_job(launch_data_t ldj, const char *label, void *context __attribute__((unused)))
{
	struct jobcb *j = job_find(label);

	if (!j)
		job_add(ldj);
}

static void reload_jobs(void)
{
	launch_data_t resp, msg = launch_data_new_string(LAUNCH_KEY_GETJOBS);
	struct jobcb *j;
	const char *l;

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		TAILQ_FOREACH(j, &jobs, tqe) {
			l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));
			if (launch_data_dict_lookup(resp, l) == NULL)
				job_remove(j);
		}
		launch_data_dict_iterate(resp, reload_job, NULL);
		launch_data_free(resp);
	} else {
		syslog(LOG_WARNING, "launch_msg(%s): %m", LAUNCH_KEY_GETJOBS);
	}
}

static void job_add(launch_data_t ajob)
{
	struct jobcb *j = calloc(1, sizeof(struct jobcb));
	launch_data_t tclc;
	const char *l;

	j->ldj = launch_data_copy(ajob);

	TAILQ_INIT(&j->wph);

	l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));

	if ((tclc = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_TCL))) {
		if ((j->tcli = Tcl_CreateInterp())) {
			Tcl_DeleteCommand(j->tcli, "exit");
			Tcl_DeleteCommand(j->tcli, "gets");
			Tcl_CreateCommand(j->tcli, "StartJob", _start_job, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "StopJob", _stop_job, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "CallBackInterval", _callback_interval, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "CallBackDate", _callback_interval, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "WatchPath", _watch_path, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "CancelAllCallBacks", _cancel_all_callbacks, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "syslog", _syslog, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "GetProperty", _getproperty, (void *)j, NULL);
			if (Tcl_Init(j->tcli) != TCL_OK)
				syslog(LOG_ERR, "Tcl_Init() for %s failed", l);
		} else {
			syslog(LOG_ERR, "Tcl_CreateInterp() for %s failed", l);
		}

		job_tcleval(j);
	}

	TAILQ_INSERT_TAIL(&jobs, j, tqe);

	syslog(LOG_INFO, "Added job: %s", l);
}

static void job_cancel_all_callbacks(struct jobcb *j)
{
	struct watchpathcb *wp;

	while ((wp = TAILQ_FIRST(&j->wph)))
		wpremove(&j->wph, wp);

	if (j->rlt) {
		CFRunLoopTimerInvalidate(j->rlt);
		CFRelease(j->rlt);
		if (j->_event)
			free(j->_event);
	}
}

static struct jobcb *job_find(const char *label)
{
	struct jobcb *j = NULL;
	const char *l;

	TAILQ_FOREACH(j, &jobs, tqe) {
		l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));
		if (!strcmp(label, l))
			break;
	}
	return j;
}

static void job_remove(struct jobcb *j)
{
	const char *l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));

	syslog(LOG_INFO, "Removing job: %s", l);
	TAILQ_REMOVE(&jobs, j, tqe);

	if (j->tcli)
		Tcl_DeleteInterp(j->tcli);
	launch_data_free(j->ldj);
	free(j);
}

static void myCFSocketCallBack(void)
{
	struct kevent kev;
	struct timespec ts = { 0, 0 };
	int r;

	r = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (r == -1) {
		syslog(LOG_NOTICE, "kevent(): %m");
	} else if (r == 0) {
		return;
	}

	if (kev.filter == EVFILT_READ && (int)kev.ident == launch_get_fd()) {
		launch_data_t resp = launch_msg(NULL);

		if (resp == NULL) {
			if (errno != 0)
				syslog(LOG_ERR, "launch_msg(): %m");
			if (errno == ECONNRESET)
				exit(EXIT_FAILURE);
			return;
		}

		if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
			syslog(LOG_NOTICE, "Unknown async message received: %s", launch_data_get_string(resp));
		} else {
			syslog(LOG_NOTICE, "Unknown async message received");
		}

		launch_data_free(resp);
	} else if (kev.filter == EVFILT_SIGNAL && kev.ident == SIGHUP) {
		syslog(LOG_INFO, "Reloading jobs");
		reload_jobs();
	} else if (kev.filter == EVFILT_VNODE) {
		struct jobcb *j = kev.udata;
		struct watchpathcb *wp = NULL;

		TAILQ_FOREACH(wp, &j->wph, tqe) {
			if (wp->fd == (int)kev.ident)
				break;
		}

		assert(wp);

		Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT);
		if (kev.fflags & NOTE_DELETE)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "delete", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
		if (kev.fflags & NOTE_WRITE)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "write", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
		if (kev.fflags & NOTE_EXTEND)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "extend", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
		if (kev.fflags & NOTE_ATTRIB)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "attrib", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
		if (kev.fflags & NOTE_LINK)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "link", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
		if (kev.fflags & NOTE_RENAME)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "rename", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);
		if (kev.fflags & NOTE_REVOKE)
			Tcl_SetVar(j->tcli, LD_EVENT_FLAGS, "revoke", TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE);

		if (wp->_event)
			Tcl_SetVar(j->tcli, LD_EVENT, wp->_event, TCL_GLOBAL_ONLY);
		job_tcleval(j);
	} else {
		syslog(LOG_WARNING, "Unknown kqueue callback");
	}
}

static void job_do_something(struct jobcb *j, const char *what)
{
	launch_data_t resp, msg, label;

	label = launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL);

	if (testtcl) {
		fprintf(stdout, "Would have sent command \"%s\" to: %s\n", what, launch_data_get_string(label));
		return;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	launch_data_dict_insert(msg, launch_data_copy(label), what);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
			if (strcmp(launch_data_get_string(resp), LAUNCH_RESPONSE_SUCCESS))
				syslog(LOG_ERR, "launch_msg(%s): %s", what, launch_data_get_string(resp));
		}
		launch_data_free(resp);
	} else {
		syslog(LOG_ERR, "launch_msg(%s): %m", what);
	}
}

static void job_start(struct jobcb *j)
{
	job_do_something(j, LAUNCH_KEY_STARTJOB);
}

static void job_stop(struct jobcb *j)
{
	job_do_something(j, LAUNCH_KEY_STOPJOB);
}

static int _callback_interval(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	struct jobcb *j = (struct jobcb *)clientData;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
        double interval;
	CFRunLoopTimerContext rlcont;
	bool use_interval = true;

	if (!strcmp(argv[0], "CallBackDate"))
		use_interval = false;

	memset(&rlcont, 0, sizeof(rlcont));
	
	rlcont.info = j; 

        if (argc < 2 || argc > 3) {
            Tcl_SetStringObj(tcl_result, "Wrong # args. Callback i ", -1);
            return TCL_ERROR;
        }

        interval = atof(argv[1]);

	if (!use_interval)
		interval -= kCFAbsoluteTimeIntervalSince1970;

	if (j->rlt) {
		CFRunLoopTimerInvalidate(j->rlt);
		CFRelease(j->rlt);
		if (j->_event)
			free(j->_event);
		j->_event = NULL;
	}

	fprintf(stderr, "@@@@@ %f\n", interval);

	if (interval > 0) {
		if (use_interval)
			j->rlt = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, interval, 0, 0, tcl_timer_callback, &rlcont);
		else
			j->rlt = CFRunLoopTimerCreate(kCFAllocatorDefault, interval , 0, 0, 0, tcl_timer_callback, &rlcont);
		if (j->rlt) {
			CFRunLoopAddTimer(CFRunLoopGetCurrent(), j->rlt, kCFRunLoopDefaultMode);
		} else {
			syslog(LOG_WARNING, "CFRunLoopTimerCreate() for some TCL based job failed");
		}
	}

	if (argc == 3)
		j->_event = strdup(argv[2]);

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static int _syslog(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	struct jobcb *j = (struct jobcb *)clientData;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
	const char *l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));
	const char *levelstr, *msg;
	int level = -1;

	if (argc != 3) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. syslog", -1);
		return TCL_ERROR;
	}

	levelstr = argv[1];
	msg = argv[2];

	if (!strcmp(levelstr, "emergency"))
		level = LOG_EMERG;
	else if (!strcmp(levelstr, "alert"))
		level = LOG_ALERT;
	else if (!strcmp(levelstr, "critical"))
		level = LOG_CRIT;
	else if (!strcmp(levelstr, "error"))
		level = LOG_ERR;
	else if (!strcmp(levelstr, "warning"))
		level = LOG_WARNING;
	else if (!strcmp(levelstr, "notice"))
		level = LOG_NOTICE;
	else if (!strcmp(levelstr, "info"))
		level = LOG_INFO;
	else if (!strcmp(levelstr, "debug"))
		level = LOG_DEBUG;

	if (level == -1) {
		Tcl_SetStringObj(tcl_result, "Bogus log level", -1);
		return TCL_ERROR;
	}

	syslog(level, "%s: %s", l, msg);

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static int _start_job(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[] __attribute__((unused)))
{
	struct jobcb *j = (struct jobcb *)clientData;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);

	if (argc != 1) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. StartJob", -1);
		return TCL_ERROR;
	}

	job_start(j);

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static int _stop_job(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[] __attribute__((unused)))
{
	struct jobcb *j = (struct jobcb *)clientData;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);

	if (argc != 1) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. StopJob", -1);
		return TCL_ERROR;
	}

	job_stop(j);

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static int _cancel_all_callbacks(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[] __attribute__((unused)))
{
	struct jobcb *j = (struct jobcb *)clientData;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);

	if (argc != 1) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. CancelAllCallBacks", -1);
		return TCL_ERROR;
	}

	job_cancel_all_callbacks(j);

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static void wpremove(struct watchpathcbhead *wph, struct watchpathcb *wp)
{
	TAILQ_REMOVE(wph, wp, tqe);
	close(wp->fd);
	free(wp->path);
	if (wp->_event)
		free(wp->_event);
	free(wp);
}

static int _watch_path(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	struct jobcb *j = (struct jobcb *)clientData;
	struct watchpathcb *wp = NULL;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
	struct kevent kev;
	int ch, fflags = 0;
	bool cancelwatch = false;


	if (argc < 3) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. WatchPath", -1);
		return TCL_ERROR;
	}

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, (char *const *)argv, "dwealrRC")) != -1) {
		switch (ch) {
		case 'd': fflags |= NOTE_DELETE; break;
		case 'w': fflags |= NOTE_WRITE;  break;
		case 'e': fflags |= NOTE_EXTEND; break;
		case 'a': fflags |= NOTE_ATTRIB; break;
		case 'l': fflags |= NOTE_LINK;   break;
		case 'r': fflags |= NOTE_RENAME; break;
		case 'R': fflags |= NOTE_REVOKE; break;
		case 'C': cancelwatch = true;    break;
		default:
			syslog(LOG_WARNING, "%s(): unknown flag", __PRETTY_FUNCTION__);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	TAILQ_FOREACH(wp, &j->wph, tqe) {
		if (!strcmp(wp->path, argv[0]))
			break;
	}

	if (wp && cancelwatch) {
		wpremove(&j->wph, wp);
		Tcl_SetIntObj(tcl_result, 0);
		return TCL_OK;
	} else if (wp == NULL) {
		wp = calloc(1, sizeof(struct watchpathcb));

		if ((wp->fd = open(wp->path, O_EVTONLY)) == -1) {
			syslog(LOG_ERR, "open(\"%s\"): %m", wp->path);
			free(wp);
			Tcl_SetStringObj(tcl_result, "Couldn't open dir", -1);
			return TCL_ERROR;
		}

		wp->path = strdup(argv[0]);

		if (argc == 2)
			wp->_event = strdup(argv[1]);

		TAILQ_INSERT_TAIL(&j->wph, wp, tqe);
	}

	EV_SET(&kev, wp->fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, fflags, 0, j);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "kevent(\"%s\"): %m", wp->path);
		wpremove(&j->wph, wp);
		Tcl_SetStringObj(tcl_result, "kevent()", -1);
		return TCL_ERROR;
	}

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static void tcl_timer_callback(CFRunLoopTimerRef timer __attribute__((unused)), void *context)
{
	struct jobcb *j = context;

	if (j->_event)
		Tcl_SetVar(j->tcli, LD_EVENT, j->_event, TCL_GLOBAL_ONLY);
	job_tcleval(j);
}

static void job_tcleval(struct jobcb *j)
{
	const char *tclcode = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_TCL));
	const char *l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));

	if (Tcl_Eval(j->tcli, tclcode) != TCL_OK)
		syslog(LOG_ERR, "%s: Tcl_Eval() failed at line %d: %s", l, j->tcli->errorLine, j->tcli->result);
	Tcl_SetVar(j->tcli, LD_EVENT, "", TCL_GLOBAL_ONLY);
}

static bool on_battery_power(void)
{
        bool result = false;
        kern_return_t kr;
        mach_port_t master_device_port;
        CFArrayRef cfarray = NULL;
        CFDictionaryRef dict;
        CFNumberRef cfnum;
        int flags;

        kr = IOMasterPort(bootstrap_port, &master_device_port);
        if (KERN_SUCCESS != kr) {
                syslog(LOG_WARNING, "IOMasterPort() failed");
                return result;
        }

        kr = IOPMCopyBatteryInfo(master_device_port, &cfarray);
        if (kIOReturnSuccess != kr) {
                /* This case handles desktop machines in addition to error cases. */
                return result;
        }

        dict = CFArrayGetValueAtIndex(cfarray, 0);
        cfnum = CFDictionaryGetValue(dict, CFSTR(kIOBatteryFlagsKey));

        if (CFNumberGetTypeID() != CFGetTypeID(cfnum)) {
                syslog(LOG_WARNING, "%s(): battery flags not a CFNumber!", __func__);
                goto out;
        }

        CFNumberGetValue(cfnum, kCFNumberLongType, &flags);

        result = !(flags & kIOPMACInstalled);

out:
        if (cfarray)
                CFRelease(cfarray);
        return result;
}

static int _getproperty(ClientData clientData __attribute__((unused)), Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);

	if (argc != 2) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. GetProperty", -1);
		return TCL_ERROR;
	}

	/* the default result is "false" */
	Tcl_SetIntObj(tcl_result, 1);

	if (!strcmp(argv[1], "onbattery")) {
		if (on_battery_power())
			Tcl_SetIntObj(tcl_result, 0);
	} else {
		Tcl_SetStringObj(tcl_result, "GetProperty: unknown property", -1);
		return TCL_ERROR;
	}

	return TCL_OK;
}
