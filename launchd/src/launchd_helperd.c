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
	char *event;
};

struct timercb {
	TAILQ_ENTRY(timercb) tqe;
	CFRunLoopTimerRef cftmr;
	char *event;
};

struct jobcb {
	TAILQ_ENTRY(jobcb) tqe;
	char *label;
	char *tclcode;
	Tcl_Interp *tcli;
	TAILQ_HEAD(timercbhead, timercb) tmrh;
	TAILQ_HEAD(watchpathcbhead, watchpathcb) wph;
};

static struct timercb *tmr_find_by_name(struct timercbhead *tmrh, const char *event);
static struct timercb *tmr_find(struct timercbhead *tmrh, CFRunLoopTimerRef cftmr);
static bool tmr_create(struct timercbhead *tmrh, double interval, const char *event, bool absol, void *context);
static void tmr_remove(struct timercbhead *tmrh, struct timercb *tmr);

static struct watchpathcb *wp_find(struct watchpathcbhead *wph, const char *event);
static bool wp_create(struct watchpathcbhead *wph, const char *path, const char *event, int fflags, void *context);
static void wp_remove(struct watchpathcbhead *wph, struct watchpathcb *wp);

static TAILQ_HEAD(jobcbhead, jobcb) jobs = TAILQ_HEAD_INITIALIZER(jobs);

static void job_add(launch_data_t j, const char *label, void *context __attribute__((unused)));
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
		launch_data_t od = launch_data_new_bool(true);
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
		launch_data_dict_insert(j, od, LAUNCH_JOBKEY_ONDEMAND);

		job_add(j, launch_data_get_string(l), NULL);

		launch_data_free(j);
	} else {
		launch_data_t resp, msg = launch_data_new_string(LAUNCH_KEY_CHECKIN);
		EV_SET(&kev, launch_get_fd(), EVFILT_READ, EV_ADD, 0, 0, 0);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_ERR, "kevent(): %m");
			exit(EXIT_FAILURE);
		}

		resp = launch_msg(msg);
		launch_data_free(msg);

		if (resp) {
			si = launch_data_dict_lookup(resp, "FileSystemSyncInterval");
			si2 = launch_data_dict_lookup(resp, "FileSystemEnergySavingSyncInterval");
		} else {
			syslog(LOG_ERR, "Failed to check in with launchd: %m");
			exit(EXIT_FAILURE);
		}

		launch_data_free(resp);

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

static void reload_jobs(void)
{
	launch_data_t resp, msg = launch_data_new_string(LAUNCH_KEY_GETJOBS);
	struct jobcb *j;

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp && launch_data_get_type(resp) == LAUNCH_DATA_DICTIONARY) {
		TAILQ_FOREACH(j, &jobs, tqe) {
			if (launch_data_dict_lookup(resp, j->label) == NULL)
				job_remove(j);
		}
		launch_data_dict_iterate(resp, job_add, NULL);
		launch_data_free(resp);
	} else {
		syslog(LOG_WARNING, "launch_msg(%s): %m", LAUNCH_KEY_GETJOBS);
	}
}

static void job_add(launch_data_t ajob, const char *label, void *context __attribute__((unused)))
{
	launch_data_t od = launch_data_dict_lookup(ajob, LAUNCH_JOBKEY_ONDEMAND);
	launch_data_t tclc = launch_data_dict_lookup(ajob, LAUNCH_JOBKEY_TCL);
	struct jobcb *j = job_find(label);
	Tcl_Interp *tcli;

	if (j) {
		if (!tclc) {
			job_remove(j);
		} else {
			free(j->tclcode);
			j->tclcode = strdup(launch_data_get_string(tclc));
		}
		return;
	}

	if (od == NULL)
		return;
	if (tclc == NULL)
		return;
	if (!launch_data_get_bool(od))
		return;

	if ((tcli = Tcl_CreateInterp()) == NULL) {
		syslog(LOG_ERR, "Tcl_CreateInterp() for %s failed", label);
		return;
	}

	j = calloc(1, sizeof(struct jobcb));

	Tcl_DeleteCommand(tcli, "exit");
	Tcl_DeleteCommand(tcli, "gets");
	Tcl_CreateCommand(tcli, "StartJob", _start_job, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "StopJob", _stop_job, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "CallBackInterval", _callback_interval, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "CallBackDate", _callback_interval, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "WatchPath", _watch_path, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "CancelAllCallBacks", _cancel_all_callbacks, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "syslog", _syslog, (void *)j, NULL);
	Tcl_CreateCommand(tcli, "GetProperty", _getproperty, (void *)j, NULL);

	if (Tcl_Init(tcli) != TCL_OK) {
		syslog(LOG_ERR, "Tcl_Init() for %s failed", label);
		free(j);
		return;
	}

	j->label = strdup(label);
	j->tclcode = strdup(launch_data_get_string(tclc));
	j->tcli = tcli;

	TAILQ_INIT(&j->tmrh);
	TAILQ_INIT(&j->wph);

	TAILQ_INSERT_TAIL(&jobs, j, tqe);

	job_tcleval(j);

	syslog(LOG_INFO, "Added job: %s", j->label);
}

static void job_cancel_all_callbacks(struct jobcb *j)
{
	struct watchpathcb *wp;
	struct timercb *tmr;

	while ((wp = TAILQ_FIRST(&j->wph)))
		wp_remove(&j->wph, wp);

	while ((tmr = TAILQ_FIRST(&j->tmrh)))
		tmr_remove(&j->tmrh, tmr);
}

static struct jobcb *job_find(const char *label)
{
	struct jobcb *j = NULL;

	TAILQ_FOREACH(j, &jobs, tqe) {
		if (!strcmp(label, j->label))
			break;
	}
	return j;
}

static void job_remove(struct jobcb *j)
{
	syslog(LOG_INFO, "Removing job: %s", j->label);

	job_cancel_all_callbacks(j);
	Tcl_DeleteInterp(j->tcli);
	free(j->tclcode);
	free(j->label);

	TAILQ_REMOVE(&jobs, j, tqe);
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

		Tcl_SetVar(j->tcli, LD_EVENT, wp->event, TCL_GLOBAL_ONLY);
		job_tcleval(j);
	} else {
		syslog(LOG_WARNING, "Unknown kqueue callback");
	}
}

static void job_do_something(struct jobcb *j, const char *what)
{
	launch_data_t resp, msg;
	int e;

	if (testtcl) {
		fprintf(stdout, "Would have sent command \"%s\" to: %s\n", what, j->label);
		return;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	launch_data_dict_insert(msg, launch_data_new_string(j->label), what);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
			if ((e = launch_data_get_errno(resp)))
				syslog(LOG_ERR, "launch_msg(%s): %s", what, strerror(e));
		} else {
			syslog(LOG_ERR, "launch_msg(%s): response not errno", what);
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
	struct timercb *tmr;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
	double interval;
	bool use_interval = true;
	const char *evname = "";

	if (!strcmp(argv[0], "CallBackDate"))
		use_interval = false;

	if (argc < 2 || argc > 3) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. Callback i ", -1);
		return TCL_ERROR;
	}

	interval = atof(argv[1]);

	if (!use_interval)
		interval -= kCFAbsoluteTimeIntervalSince1970;

	if (argc == 3)
		evname = argv[2];

	tmr = tmr_find_by_name(&j->tmrh, evname);

	if (interval <= 0) {
		Tcl_SetStringObj(tcl_result, "Non-positive interval: Callback i ", -1);
		return TCL_ERROR;
	}

	if (tmr)
		tmr_remove(&j->tmrh, tmr);

	if (!tmr_create(&j->tmrh, interval, evname, !use_interval, j)) {
		Tcl_SetStringObj(tcl_result, "Failed to add timer callback ", -1);
		return TCL_ERROR;
	}

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static int _syslog(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	struct jobcb *j = (struct jobcb *)clientData;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
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

	syslog(level, "%s: %s", j->label, msg);

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

static struct watchpathcb *wp_find(struct watchpathcbhead *wph, const char *event)
{
	struct watchpathcb *r = NULL;

	TAILQ_FOREACH(r, wph, tqe) {
		if (!strcmp(r->event, event))
			break;
	}

	return r;
}

static bool wp_create(struct watchpathcbhead *wph, const char *path, const char *event, int fflags, void *context)
{
	struct watchpathcb *wp;
	struct kevent kev;
	int fd;

	if ((fd = open(path, O_EVTONLY)) == -1) {
		syslog(LOG_ERR, "open(\"%s\"): %m", path);
		return false;
	}

	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, fflags, 0, context);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "kevent(\"%s\"): %m", path);
		close(fd);
		return false;
	}

	wp = calloc(1, sizeof(struct watchpathcb));

	wp->fd = fd;
	wp->path = strdup(path);
	wp->event = strdup(event);

	TAILQ_INSERT_TAIL(wph, wp, tqe);

	return true;
}

static void wp_remove(struct watchpathcbhead *wph, struct watchpathcb *wp)
{
	TAILQ_REMOVE(wph, wp, tqe);
	close(wp->fd);
	free(wp->path);
	free(wp->event);
	free(wp);
}

static int _watch_path(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[])
{
	struct jobcb *j = (struct jobcb *)clientData;
	struct watchpathcb *wp = NULL;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
	int ch, fflags = 0;
	bool cancelwatch = false;
	const char *evname = "";

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

	if (argc == 2)
		evname = argv[1];

	wp = wp_find(&j->wph, evname);

	if (cancelwatch) {
		if (wp) {
			wp_remove(&j->wph, wp);
			Tcl_SetIntObj(tcl_result, 0);
			return TCL_OK;
		} else {
			Tcl_SetStringObj(tcl_result, "Couldn't find watchpath", -1);
			return TCL_ERROR;
		}
	}
	
	if (wp)
		wp_remove(&j->wph, wp);

	if (!wp_create(&j->wph, argv[0], evname, fflags, j)) {
		Tcl_SetStringObj(tcl_result, "Couldn't create watchpath callback", -1);
		return TCL_ERROR;
	}

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static void tcl_timer_callback(CFRunLoopTimerRef timer, void *context)
{
	struct jobcb *j = context;
	struct timercb *tmr = tmr_find(&j->tmrh, timer);

	if (tmr) {
		Tcl_SetVar(j->tcli, LD_EVENT, tmr->event, TCL_GLOBAL_ONLY);
		job_tcleval(j);
	} else {
		syslog(LOG_ERR, "%s: Couldn't find timer by ref!", j->label);
	}
}

static void job_tcleval(struct jobcb *j)
{
	if (Tcl_Eval(j->tcli, j->tclcode) != TCL_OK)
		syslog(LOG_ERR, "%s: Tcl_Eval() failed at line %d: %s", j->label, j->tcli->errorLine, j->tcli->result);
	Tcl_SetVar(j->tcli, LD_EVENT, "", TCL_GLOBAL_ONLY);
}

static bool on_battery_power(void)
{
	bool result = false;
	kern_return_t kr;
	CFArrayRef cfarray = NULL;
	CFDictionaryRef dict;
	CFNumberRef cfnum;
	int flags;

	kr = IOPMCopyBatteryInfo(kIOMasterPortDefault, &cfarray);
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

static void tmr_remove(struct timercbhead *tmrh, struct timercb *tmr)
{
	TAILQ_REMOVE(tmrh, tmr, tqe);
	CFRunLoopTimerInvalidate(tmr->cftmr);
	CFRelease(tmr->cftmr);
	free(tmr->event);
	free(tmr);
}

static struct timercb *tmr_find_by_name(struct timercbhead *tmrh, const char *event)
{
	struct timercb *r = NULL;

	TAILQ_FOREACH(r, tmrh, tqe) {
		if (!strcmp(r->event, event))
			break;
	}

	return r;
}

static struct timercb *tmr_find(struct timercbhead *tmrh, CFRunLoopTimerRef cftmr)
{
	struct timercb *r = NULL;

	TAILQ_FOREACH(r, tmrh, tqe) {
		if (r->cftmr == cftmr)
			break;
	}

	return r;
}

static bool tmr_create(struct timercbhead *tmrh, double interval, const char *event, bool absol, void *context)
{
	CFRunLoopTimerRef cftmr;
	CFRunLoopTimerContext rlcont;
	struct timercb *tmr;

	memset(&rlcont, 0, sizeof(rlcont));
	rlcont.info = context; 

	if (absol)
		cftmr = CFRunLoopTimerCreate(kCFAllocatorDefault, interval, 0, 0, 0, tcl_timer_callback, &rlcont);
	else
		cftmr = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, interval, 0, 0, tcl_timer_callback, &rlcont);

	if (cftmr) {
		CFRunLoopAddTimer(CFRunLoopGetCurrent(), cftmr, kCFRunLoopDefaultMode);
	} else {
		syslog(LOG_WARNING, "CFRunLoopTimerCreate() for some TCL based job failed");
		return false;
	}

	tmr = calloc(1, sizeof(struct timercb));

	tmr->cftmr = cftmr;
	tmr->event = strdup(event);

	TAILQ_INSERT_TAIL(tmrh, tmr, tqe);

	return true;
}
