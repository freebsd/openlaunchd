#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <tcl.h>

#include "launch.h"

#define kHelperdTCLState CFSTR("__TCLstate__")
#define kHelperdTCLCallbackState CFSTR("__TCLCallbackState__")

static void myCFSocketCallBack(void);
static void sync_callback(CFRunLoopTimerRef, void *);
static void tcl_callback(CFRunLoopTimerRef, void *);
static void close_all_fds(launch_data_t);
static CFTypeRef ld2CF(launch_data_t o);
static void addjob(launch_data_t j);
static void removejob(const char *label);
static void runjob(CFMutableDictionaryRef j);

static CFMutableDictionaryRef ldself = NULL;
static CFMutableDictionaryRef alljobs = NULL;

static int _run_job(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int _callback_interval(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);

int main(void)
{
	launch_data_t resp, msg = launch_data_alloc(LAUNCH_DATA_STRING);
	CFRunLoopSourceRef sockrlr = NULL;
	CFSocketRef sockr = NULL;
	CFRunLoopTimerRef syncr = NULL;

	alljobs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	openlog(getprogname(), LOG_PID|LOG_CONS, LOG_DAEMON);

	sockr = CFSocketCreateWithNative(kCFAllocatorDefault, launch_get_fd(), kCFSocketReadCallBack, (CFSocketCallBack)myCFSocketCallBack, NULL);
	if (sockr)
		sockrlr = CFSocketCreateRunLoopSource(kCFAllocatorDefault, sockr, 0);
	if (sockrlr)
		CFRunLoopAddSource(CFRunLoopGetCurrent(), sockrlr, kCFRunLoopDefaultMode);
	else
		exit(EXIT_FAILURE);

	launch_data_set_string(msg, LAUNCH_KEY_CHECKIN);
	ldself = (CFMutableDictionaryRef)ld2CF(launch_msg(msg));

	launch_data_set_string(msg, LAUNCH_KEY_GETJOBS);
	resp = launch_msg(msg);
	
	launch_data_free(msg);

	if (resp) {
		close_all_fds(resp);

		launch_data_dict_iterate(resp, (void (*)(launch_data_t, const char *, void *))addjob, NULL);

		launch_data_free(resp);
	} else {
		syslog(LOG_WARNING, "launch_msg(%s): %m", LAUNCH_KEY_GETJOBS);
	}

	syncr = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, 30, 0, 0, sync_callback, NULL);
	if (syncr)
		CFRunLoopAddTimer(CFRunLoopGetCurrent(), syncr, kCFRunLoopDefaultMode);
	else
		syslog(LOG_WARNING, "CFRunLoopTimerCreate() failed");

	CFRunLoopRun();

	exit(EXIT_SUCCESS);
}

static void addjob(launch_data_t j)
{
	launch_data_t l = launch_data_dict_lookup(j, LAUNCH_JOBKEY_LABEL);
	launch_data_t tclc = launch_data_dict_lookup(j, LAUNCH_JOBKEY_TCL);
	const char *ckey = launch_data_get_string(l);
	CFStringRef key = CFStringCreateWithBytes(kCFAllocatorDefault, ckey, strlen(ckey), kCFStringEncodingUTF8, false);
	CFMutableDictionaryRef value = (CFMutableDictionaryRef)ld2CF(j);

	if (tclc) {
		CFDataRef cfdr;
		Tcl_Interp *interp;

		if ((interp = Tcl_CreateInterp())) {
			Tcl_CreateObjCommand(interp, "RunJob", _run_job, (void *)value, NULL);
			Tcl_CreateObjCommand(interp, "CallBackInterval", _callback_interval, (void *)value, NULL);
			if (Tcl_Init(interp) != TCL_OK)
				syslog(LOG_ERR, "Tcl_Init() for %s failed", ckey);
		} else {
			syslog(LOG_ERR, "Tcl_CreateInterp() for %s failed", ckey);
		}

		cfdr = CFDataCreate(kCFAllocatorDefault, (UInt8 *)&interp, sizeof(interp)); 
		CFDictionarySetValue(value, kHelperdTCLState, cfdr);
		CFRelease(cfdr);

		if (Tcl_Eval(interp, launch_data_get_string(tclc)) != TCL_OK) {
			syslog(LOG_ERR, "Tcl_Eval() for %s failed", ckey);
		}
	}

	CFDictionarySetValue(alljobs, key, value);
	CFRelease(key);
	CFRelease(value);

	syslog(LOG_INFO, "Added job: %s", ckey);
}

static void removejob(const char *label)
{
	CFStringRef key = CFStringCreateWithBytes(kCFAllocatorDefault, label, strlen(label), kCFStringEncodingUTF8, false);
	CFMutableDictionaryRef j;
	CFDataRef cfdr;

	if (CFDictionaryGetValueIfPresent(alljobs, key, (const void **)&j)) {
		if (CFDictionaryGetValueIfPresent(j, kHelperdTCLState, (const void **)&cfdr))
			Tcl_DeleteInterp(*(Tcl_Interp **)CFDataGetBytePtr(cfdr));
	}

	CFDictionaryRemoveValue(alljobs, key);
	CFRelease(key);

	syslog(LOG_INFO, "Removed job: %s", label);
}

static void myCFSocketCallBack(void)
{
	launch_data_t resp = launch_msg(NULL);
	launch_data_t tmp;

	if (resp == NULL) {
		if (errno != 0)
			syslog(LOG_ERR, "launch_msg(): %m");
		return;
	}

	close_all_fds(resp);

	if (launch_data_get_type(resp) == LAUNCH_DATA_DICTIONARY) {
		if ((tmp = launch_data_dict_lookup(resp, LAUNCH_KEY_SUBMITJOB))) {
			addjob(tmp);
		} else if ((tmp = launch_data_dict_lookup(resp, LAUNCH_KEY_REMOVEJOB))) {
			removejob(launch_data_get_string(tmp));
		} else {
			syslog(LOG_NOTICE, "Unknown async dictionary received");
		}
	} else {
		syslog(LOG_NOTICE, "Unknown async message received");
	}

	launch_data_free(resp);
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

static void sync_callback(CFRunLoopTimerRef timer __attribute__((unused)), void *context __attribute__((unused)))
{
	sync();
}


static void runjob(CFMutableDictionaryRef j)
{
        CFStringRef cflabel;
	launch_data_t resp, msg, label;
	char buf[1024];

	label = launch_data_alloc(LAUNCH_DATA_STRING);
	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	cflabel = CFDictionaryGetValue(j, CFSTR(LAUNCH_JOBKEY_LABEL));

	CFStringGetCString(cflabel, buf, sizeof(buf), kCFStringEncodingUTF8);
	launch_data_set_string(label, buf);
	launch_data_dict_insert(msg, label, LAUNCH_KEY_STARTJOB);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
			if (strcmp(launch_data_get_string(resp), LAUNCH_RESPONSE_SUCCESS))
				syslog(LOG_ERR, "launch_msg(%s): %s", LAUNCH_KEY_STARTJOB, launch_data_get_string(resp));
		}
		launch_data_free(resp);
	} else {
		syslog(LOG_ERR, "launch_msg(%s): %m", LAUNCH_KEY_STARTJOB);
	}
}

static void _launch_dict_callback(launch_data_t o, const char *key, void *context)
{
        CFMutableDictionaryRef dict = (CFMutableDictionaryRef)context;
        CFStringRef keyString = CFStringCreateWithBytes(kCFAllocatorDefault, key, strlen(key), kCFStringEncodingUTF8, false);
        CFTypeRef value = ld2CF(o);
        CFDictionarySetValue(dict, keyString, value);
        CFRelease(keyString);
        CFRelease(value);
}

static CFTypeRef ld2CF(launch_data_t o)
{
	if (launch_data_get_type(o) == LAUNCH_DATA_DICTIONARY) {
		CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		if (dict == NULL)
			return NULL;
		launch_data_dict_iterate(o, _launch_dict_callback, dict);
		return dict;
	} else if (launch_data_get_type(o) == LAUNCH_DATA_ARRAY) {
		size_t i, count = launch_data_array_get_count(o);
		CFMutableArrayRef array = CFArrayCreateMutable(kCFAllocatorDefault, count, &kCFTypeArrayCallBacks);
		for (i = 0; i < count; i++)
			CFArraySetValueAtIndex(array, i, ld2CF(launch_data_array_get_index(o, i)));
		return array;
	} else if (launch_data_get_type(o) == LAUNCH_DATA_FD) {
		int value = launch_data_get_fd(o);
		return CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &value);
	} else if (launch_data_get_type(o) == LAUNCH_DATA_INTEGER) {
		long long value = launch_data_get_integer(o);
		return CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &value);
	} else if (launch_data_get_type(o) == LAUNCH_DATA_REAL) {
		double value = launch_data_get_real(o);
		return CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &value);
	} else if (launch_data_get_type(o) == LAUNCH_DATA_BOOL) {
		return launch_data_get_bool(o) ? kCFBooleanTrue : kCFBooleanFalse;
	} else if (launch_data_get_type(o) == LAUNCH_DATA_STRING) {
		const char *value = launch_data_get_string(o);
		return CFStringCreateWithBytes(kCFAllocatorDefault, value, strlen(value), kCFStringEncodingUTF8, false);
	} else if (launch_data_get_type(o) == LAUNCH_DATA_OPAQUE) {
		return CFDataCreate(kCFAllocatorDefault, launch_data_get_opaque(o), launch_data_get_opaque_size(o));
	}
	return NULL;
}

static int _callback_interval(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	CFMutableDictionaryRef j = (CFMutableDictionaryRef)clientData;
	CFRunLoopTimerRef rltr;
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
        int  interval;
	CFRunLoopTimerContext rlcont;

	memset(&rlcont, 0, sizeof(rlcont));
	
	rlcont.info = j; 

        if (objc != 2) {
            Tcl_SetStringObj(tcl_result, "Wrong # args. CallbackInterval i ", -1);
            return TCL_ERROR;
        }

        if (Tcl_GetIntFromObj(interp, objv[1], &interval) == TCL_ERROR)
		return TCL_ERROR;

	rltr = CFRunLoopTimerCreate(kCFAllocatorDefault, 0, interval, 0, 0, tcl_callback, &rlcont);
	if (rltr) {
		CFRunLoopAddTimer(CFRunLoopGetCurrent(), rltr, kCFRunLoopDefaultMode);
		CFDictionarySetValue(j, kHelperdTCLCallbackState, rltr);
		CFRelease(rltr);
	} else {
		syslog(LOG_WARNING, "CFRunLoopTimerCreate() for some TCL based job failed");
	}

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static int _run_job(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[] __attribute__((unused)))
{
	CFMutableDictionaryRef j = (CFMutableDictionaryRef)clientData;
	Tcl_Obj * tcl_result = Tcl_GetObjResult(interp);

	if (objc != 1) {
		Tcl_SetStringObj(tcl_result, "Wrong # args. RunJob", -1);
		return TCL_ERROR;
	}

	runjob(j);

	Tcl_SetIntObj(tcl_result, 0);
	return TCL_OK;
}

static void tcl_callback(CFRunLoopTimerRef timer __attribute__((unused)), void *context)
{
	CFMutableDictionaryRef j = context;
	CFStringRef cftclcode;
	CFDataRef cfdr;
	Tcl_Interp *interp;
	size_t bufsz = 4096;
	char * buf = malloc(4096);

	cftclcode = CFDictionaryGetValue(j, CFSTR(LAUNCH_JOBKEY_TCL));
	cfdr = CFDictionaryGetValue(j, kHelperdTCLState);
	interp = *(Tcl_Interp **)CFDataGetBytePtr(cfdr);

	while (!CFStringGetCString(cftclcode, buf, bufsz - 1, kCFStringEncodingUTF8)) {
		free(buf);
		bufsz *= 2;
		buf = malloc(bufsz);
	}

	if (Tcl_Eval(interp, buf) != TCL_OK) {
		syslog(LOG_ERR, "Tcl_Eval() for some TCL based job failed");
	}

	free(buf);
}
