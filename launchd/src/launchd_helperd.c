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

static void myCFSocketCallBack(void);
static void tcl_timer_callback(CFRunLoopTimerRef, void *);

static void close_all_fds(launch_data_t);

static void job_add(launch_data_t j);
static void job_remove(const char *label);
static void job_start(struct jobcb *j);
static void job_stop(struct jobcb *j);
static void job_tcleval(struct jobcb *j);
static void job_cancel_all_callbacks(struct jobcb *j);

static launch_data_t ldself = NULL;

static int kq = 0;
static char *testtcl = NULL;

static int _start_job(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _stop_job(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _callback_interval(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _watch_path(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _cancel_all_callbacks(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);
static int _syslog(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);

int main(int argc, char *argv[])
{
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

	openlog(getprogname(), LOG_PID|LOG_CONS|(testtcl ? LOG_PERROR : 0), LOG_DAEMON);

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR, "kqueue(): %m");
		exit(EXIT_FAILURE);
	}

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
		launch_data_t resp, msg = launch_data_alloc(LAUNCH_DATA_STRING);
		EV_SET(&kev, launch_get_fd(), EVFILT_READ, EV_ADD, 0, 0, 0);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_ERR, "kevent(): %m");
			exit(EXIT_FAILURE);
		}

		launch_data_set_string(msg, LAUNCH_KEY_CHECKIN);
		ldself = launch_msg(msg);

		launch_data_set_string(msg, LAUNCH_KEY_GETJOBS);
		resp = launch_msg(msg);
		launch_data_free(msg);

		if (resp) {
			close_all_fds(resp);
			launch_data_dict_iterate(resp, (void (*)(launch_data_t, const char *, void *))job_add, NULL);
			launch_data_free(resp);
		} else {
			syslog(LOG_WARNING, "launch_msg(%s): %m", LAUNCH_KEY_GETJOBS);
		}
	}

	sockr = CFSocketCreateWithNative(kCFAllocatorDefault, kq, kCFSocketReadCallBack, (CFSocketCallBack)myCFSocketCallBack, NULL);
	if (sockr)
		sockrlr = CFSocketCreateRunLoopSource(kCFAllocatorDefault, sockr, 0);
	if (sockrlr)
		CFRunLoopAddSource(CFRunLoopGetCurrent(), sockrlr, kCFRunLoopDefaultMode);
	else
		exit(EXIT_FAILURE);

	syncr = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, 30, 0, 0, (CFRunLoopTimerCallBack)sync, NULL);
	if (syncr)
		CFRunLoopAddTimer(CFRunLoopGetCurrent(), syncr, kCFRunLoopDefaultMode);
	else
		syslog(LOG_WARNING, "CFRunLoopTimerCreate() failed");

	CFRunLoopRun();

	exit(EXIT_SUCCESS);
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
			Tcl_CreateCommand(j->tcli, "WatchPath", _watch_path, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "CancelAllCallBacks", _cancel_all_callbacks, (void *)j, NULL);
			Tcl_CreateCommand(j->tcli, "syslog", _syslog, (void *)j, NULL);
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

static void job_remove(const char *label)
{
	struct jobcb *j = NULL;
	const char *l;

	TAILQ_FOREACH(j, &jobs, tqe) {
		l = launch_data_get_string(launch_data_dict_lookup(j->ldj, LAUNCH_JOBKEY_LABEL));
		if (!strcmp(label, l))
			break;
	}

	if (j == NULL) {
		syslog(LOG_WARNING, "Couldn't find job \"%s\" to remove!", label);
		return;
	}
	
	TAILQ_REMOVE(&jobs, j, tqe);

	if (j->tcli)
		Tcl_DeleteInterp(j->tcli);
	launch_data_free(j->ldj);
	free(j);
	syslog(LOG_INFO, "Removed job: %s", label);
}

static void myCFSocketCallBack(void)
{
	launch_data_t resp, tmp;
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
		resp = launch_msg(NULL);

		if (resp == NULL) {
			if (errno != 0)
				syslog(LOG_ERR, "launch_msg(): %m");
			return;
		}

		close_all_fds(resp);

		if (launch_data_get_type(resp) == LAUNCH_DATA_DICTIONARY) {
			if ((tmp = launch_data_dict_lookup(resp, LAUNCH_KEY_SUBMITJOB))) {
				job_add(tmp);
			} else if ((tmp = launch_data_dict_lookup(resp, LAUNCH_KEY_REMOVEJOB))) {
				job_remove(launch_data_get_string(tmp));
			} else {
				syslog(LOG_NOTICE, "Unknown async dictionary received");
			}
		} else {
			syslog(LOG_NOTICE, "Unknown async message received");
		}

		launch_data_free(resp);
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

static void close_all_fds(launch_data_t o)
{

	if (launch_data_get_type(o) == LAUNCH_DATA_FD) {
		close(launch_data_get_fd(o));
		launch_data_set_fd(o, -1);
	} else if (launch_data_get_type(o) == LAUNCH_DATA_DICTIONARY) {
		launch_data_dict_iterate(o, (void (*)(launch_data_t, const char *, void *))close_all_fds, NULL);
	} else if (launch_data_get_type(o) == LAUNCH_DATA_ARRAY) {
		size_t i;
		for (i = 0; i < launch_data_array_get_count(o); i++) {
			launch_data_t t = launch_data_array_get_index(o, i);
			close_all_fds(t);
		}
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
        int  interval;
	CFRunLoopTimerContext rlcont;

	memset(&rlcont, 0, sizeof(rlcont));
	
	rlcont.info = j; 

        if (argc < 2 || argc > 3) {
            Tcl_SetStringObj(tcl_result, "Wrong # args. CallbackInterval i ", -1);
            return TCL_ERROR;
        }

        interval = atoi(argv[1]);

	if (j->rlt) {
		CFRunLoopTimerInvalidate(j->rlt);
		CFRelease(j->rlt);
		if (j->_event)
			free(j->_event);
		j->_event = NULL;
	}

	if (interval > 0) {
		j->rlt = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, interval, 0, 0, tcl_timer_callback, &rlcont);
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
