#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <syslog.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <dns_sd.h>
#include <tcl.h>

#include "launch.h"

#define LAUNCH_SECDIR "/tmp/launch-XXXXXX"

static void distill_config_file(launch_data_t);
static void sock_dict_cb(launch_data_t what, const char *key, void *context);
static void sock_dict_edit_entry(launch_data_t tmp, const char *key);
static launch_data_t CF2launch_data(CFTypeRef);
static CFPropertyListRef CreateMyPropertyListFromFile(const char *);
static void WriteMyPropertyListToFile(CFPropertyListRef, const char *);
static void readcfg(const char *, bool load, bool editondisk);
static void update_plist(CFPropertyListRef, const char *, bool);
static int _fd(int);
static int demux_cmd(int argc, char *const argv[]);
static void wait4path(const char *path);

static int lctl_tcl_cmd(ClientData clientData, Tcl_Interp *interp, int argc, CONST char *argv[]);

static int load_and_unload_cmd(int argc, char *const argv[]);
//static int reload_cmd(int argc, char *const argv[]);
static int start_and_stop_cmd(int argc, char *const argv[]);
static int list_cmd(int argc, char *const argv[]);

static int setenv_cmd(int argc, char *const argv[]);
static int unsetenv_cmd(int argc, char *const argv[]);
static int getenv_and_export_cmd(int argc, char *const argv[]);

static int limit_cmd(int argc, char *const argv[]);
static int stdio_cmd(int argc, char *const argv[]);
static int fyi_cmd(int argc, char *const argv[]);
static int logupdate_cmd(int argc, char *const argv[]);
static int umask_cmd(int argc, char *const argv[]);

static int help_cmd(int argc, char *const argv[]);

static const struct {
	const char *name;
	int (*func)(int argc, char *const argv[]);
	const char *desc;
} cmds[] = {
	{ "load",	load_and_unload_cmd,	"Load configuration files and/or directories" },
	{ "unload",	load_and_unload_cmd,	"Unload configuration files and/or directories" },
//	{ "reload",	reload_cmd,		"Reload configuration files and/or directories" },
	{ "start",	start_and_stop_cmd,	"Start specified jobs" },
	{ "stop",	start_and_stop_cmd,	"Stop specified jobs" },
	{ "list",	list_cmd,		"List jobs and information about jobs" },
	{ "setenv",	setenv_cmd,		"Set an environmental variable in launchd" },
	{ "unsetenv",	unsetenv_cmd,		"Unset an environmental variable in launchd" },
	{ "getenv",	getenv_and_export_cmd,	"Get an environmental variable from launchd" },
	{ "export",	getenv_and_export_cmd,	"Export shell settings from launchd" },
	{ "limit",	limit_cmd,		"View and adjust launchd resource limits" },
	{ "stdout",	stdio_cmd,		"Redirect launchd's standard out to the given path" },
	{ "stderr",	stdio_cmd,		"Redirect launchd's standard error to the given path" },
	{ "shutdown",	fyi_cmd,		"Prepare for system shutdown" },
	{ "reloadttys",	fyi_cmd,		"Reload /etc/ttys" },
	{ "log",	logupdate_cmd,		"Adjust the logging level or mask of launchd" },
	{ "umask",	umask_cmd,		"Change launchd's umask" },
	{ "help",	help_cmd,		"This help output" },
};

int main(int argc, char *const argv[])
{
	Tcl_Interp *interp;
	char *l;
	int ch;
	size_t i;
	bool wflag = false, legacymode = false;

	while ((ch = getopt(argc, argv, "l:u:w")) != -1) {
		legacymode = true;
		switch (ch) {
		case 'w':
			wflag = true;
			break;
		case 'l':
			fprintf(stderr, "%s usage: \"-l\" is deprecated, please use \"load\"\n", getprogname());
			readcfg(optarg, true, wflag);
			break;
		case 'u':
			fprintf(stderr, "%s usage: \"-u\" is deprecated, please use \"unload\"\n", getprogname());
			readcfg(optarg, false, wflag);
			break;
		default:
			help_cmd(0, NULL);
			exit(EXIT_FAILURE);
		}
	}

	if (legacymode)
		exit(EXIT_SUCCESS);

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		exit(demux_cmd(argc, argv));
	}

	interp = Tcl_CreateInterp();

	if (interp == NULL) {
		fprintf(stderr, "Tcl_CreateInterp() failed\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++)
		Tcl_CreateCommand(interp, cmds[i].name, lctl_tcl_cmd, 0, 0);

	if (isatty(STDIN_FILENO)) {
		while ((l = readline("launchd % "))) {
			if (Tcl_Eval(interp, l) != TCL_OK)
				fprintf(stderr, "%s at line %d: %s\n", getprogname(), interp->errorLine, interp->result);
			free(l);
		}
		fputc('\n', stdout);
	} else if (Tcl_EvalFile(interp, "/dev/stdin") != TCL_OK) {
		fprintf(stderr, "%s at line %d: %s\n", getprogname(), interp->errorLine, interp->result);
	}

	Tcl_DeleteInterp(interp);

	exit(EXIT_SUCCESS);
}

static int demux_cmd(int argc, char *const argv[])
{
	size_t i;

	optind = 1;
	optreset = 1;

	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++) {
		if (!strcmp(cmds[i].name, argv[0]))
			return cmds[i].func(argc, argv);
	}

	fprintf(stderr, "%s: unknown subcommand \"%s\"\n", getprogname(), argv[0]);
	return 1;
}

static int lctl_tcl_cmd(ClientData clientData __attribute__((unused)), Tcl_Interp *interp, int argc, CONST char *argv[])
{
	Tcl_Obj *tcl_result = Tcl_GetObjResult(interp);
	int r = demux_cmd(argc, (char *const *)argv);

	Tcl_SetIntObj(tcl_result, r);
	if (r)
		return TCL_ERROR;
	return TCL_OK;
}

static int unsetenv_cmd(int argc, char *const argv[])
{
	launch_data_t resp, tmp, msg;

	if (argc != 2) {
		fprintf(stderr, "%s usage: unsetenv <key>\n", getprogname());
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmp = launch_data_new_string(argv[1]);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_UNSETUSERENVIRONMENT);

	resp = launch_msg(msg);

	launch_data_free(msg);

	if (resp) {
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"%s\"): %s\n", LAUNCH_KEY_UNSETUSERENVIRONMENT, strerror(errno));
	}

	return 0;
}

static int setenv_cmd(int argc, char *const argv[])
{
	launch_data_t resp, tmp, tmpv, msg;

	if (argc != 3) {
		fprintf(stderr, "%s usage: setenv <key> <value>\n", getprogname());
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmpv = launch_data_new_string(argv[2]);
	launch_data_dict_insert(tmp, tmpv, argv[1]);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETUSERENVIRONMENT);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"%s\"): %s\n", LAUNCH_KEY_SETUSERENVIRONMENT, strerror(errno));
	}

	return 0;
}

static int getenv_and_export_cmd(int argc, char *const argv[] __attribute__((unused)))
{
	launch_data_t resp, msg;
	bool is_csh = false;
	const char *k;
	void print_launchd_env(launch_data_t obj, const char *key, void *context __attribute__((unused))) {
		if (is_csh)
			fprintf(stdout, "setenv %s %s;\n", key, launch_data_get_string(obj));
		else
			fprintf(stdout, "%s=%s; export %s;\n", key, launch_data_get_string(obj), key);
	}
	void print_key_value(launch_data_t obj, const char *key, void *context __attribute__((unused))) {
		if (!strcmp(key, k))
			fprintf(stdout, "%s\n", launch_data_get_string(obj));
	}
	
	if (!strcmp(argv[0], "export")) {
		char *s = getenv("SHELL");
		if (s)
			is_csh = strstr(s, "csh") ? true : false;
	} else if (argc != 2) {
		fprintf(stderr, "%s usage: getenv <key>\n", getprogname());
		return 1;
	}

	k = argv[1];

	msg = launch_data_new_string(LAUNCH_KEY_GETUSERENVIRONMENT);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		launch_data_dict_iterate(resp, (!strcmp(argv[0], "export")) ? print_launchd_env : print_key_value, NULL);
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"" LAUNCH_KEY_GETUSERENVIRONMENT "\"): %s\n", strerror(errno));
	}
	return 0;
}

static void unloadjob(launch_data_t job)
{
	launch_data_t resp, tmp, tmps, msg;
	int e;

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_alloc(LAUNCH_DATA_STRING);
	tmps = launch_data_dict_lookup(job, LAUNCH_JOBKEY_LABEL);

	if (!tmps) {
		fprintf(stderr, "%s: Error: Missing Key: %s\n", getprogname(), LAUNCH_JOBKEY_LABEL);
		return;
	}

	launch_data_set_string(tmp, launch_data_get_string(tmps));
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_REMOVEJOB);
	resp = launch_msg(msg);
	launch_data_free(msg);
	if (LAUNCH_DATA_ERRNO == launch_data_get_type(resp)) {
		if ((e = launch_data_get_errno(resp)))
			fprintf(stderr, "%s\n", strerror(e));
	}
	launch_data_free(resp);
}

static void update_plist(CFPropertyListRef plist, const char *where, bool load)
{
	if (load) {
		CFDictionaryRemoveValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED));
		CFDictionaryRemoveValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_ENABLED));
	} else {
		CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED), kCFBooleanTrue);
	}

	WriteMyPropertyListToFile(plist, where);
}

static void readcfg(const char *what, bool load, bool editondisk)
{
	launch_data_t resp, msg, tmp, tmpe, tmpd, tmpa, id_plist;
	CFPropertyListRef plist;
	DIR *d;
	struct dirent *de;
	struct stat sb;
	char *foo;
	bool job_disabled;
	int e;

	if (stat(what, &sb) == -1)
		return;

	if (S_ISREG(sb.st_mode) && !(sb.st_mode & S_IWOTH)) {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		plist = CreateMyPropertyListFromFile(what);
		if (!plist) {
			fprintf(stderr, "%s: no plist was returned for: %s\n", getprogname(), what);
			return;
		}

		if (editondisk)
			update_plist(plist, what, load);

		id_plist = CF2launch_data(plist);

		tmpe = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_ENABLED);
		tmpd = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_DISABLED);
		if (tmpd)
			job_disabled = launch_data_get_bool(tmpd);
		else if (tmpe)
			job_disabled = !launch_data_get_bool(tmpe);
		else
			job_disabled = false;

		if (job_disabled || !load) {
			unloadjob(id_plist);
			launch_data_free(id_plist);
			return;
		}
		distill_config_file(id_plist);
		launch_data_dict_insert(msg, id_plist, LAUNCH_KEY_SUBMITJOB);
	} else {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		tmpa = launch_data_alloc(LAUNCH_DATA_ARRAY);
		if ((d = opendir(what)) == NULL) {
			fprintf(stderr, "%s: opendir() failed to open the directory\n", getprogname());
			exit(EXIT_FAILURE);
		}

		while ((de = readdir(d)) != NULL) {
			if ((de->d_name[0] == '.'))
				continue;
			asprintf(&foo, "%s/%s", what, de->d_name);
			plist = CreateMyPropertyListFromFile(foo);
			if (!plist) {
				fprintf(stderr, "%s: no plist was returned for: %s\n", getprogname(), foo);
				free(foo);
				continue;
			}
			free(foo);
			id_plist = CF2launch_data(plist);
			if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_DISABLED))) {
				if (launch_data_get_bool(tmp)) {
					launch_data_free(id_plist);
					continue;
				}
			}
			distill_config_file(id_plist);
			launch_data_array_set_index(tmpa, id_plist, launch_data_array_get_count(tmpa));
		}
		closedir(d);
		if (launch_data_array_get_count(tmpa) == 0) {
			launch_data_free(tmpa);
			launch_data_free(msg);
			return;
		}
		launch_data_dict_insert(msg, tmpa, LAUNCH_KEY_SUBMITJOB);
	}

	resp = launch_msg(msg);

	if (resp) {
		if (LAUNCH_DATA_ERRNO == launch_data_get_type(resp)) {
			if ((e = launch_data_get_errno(resp)))
				fprintf(stderr, "%s\n", strerror(e));
		}
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
	}
}

static void distill_config_file(launch_data_t id_plist)
{
	launch_data_t tmp;

	if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_USERNAME))) {
		struct passwd *pwe = getpwnam(launch_data_get_string(tmp));
		if (pwe) {
			launch_data_t ntmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
			launch_data_set_integer(ntmp, pwe->pw_uid);
			launch_data_dict_insert(id_plist, ntmp, LAUNCH_JOBKEY_UID);
		}
	}

	if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_GROUPNAME))) {
		struct group *gre = getgrnam(launch_data_get_string(tmp));
		if (gre) {
			launch_data_t ntmp = launch_data_alloc(LAUNCH_DATA_INTEGER);
			launch_data_set_integer(ntmp, gre->gr_gid);
			launch_data_dict_insert(id_plist, ntmp, LAUNCH_JOBKEY_GID);
		}
	}

	if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_SOCKETS)))
		launch_data_dict_iterate(tmp, sock_dict_cb, id_plist);
}

static launch_data_t create_launch_data_addrinfo_fd(struct addrinfo *ai, int fd)
{
	launch_data_t t, d = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (ai->ai_flags & AI_PASSIVE) {
		t = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(t, true);
		launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_PASSIVE);
	}

	if (ai->ai_family) {
		t = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(t, ai->ai_family);
		launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_FAMILY);
	}

	if (ai->ai_socktype) {
		t = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(t, ai->ai_socktype);
		launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_SOCKTYPE);
	}

	if (ai->ai_protocol) {
		t = launch_data_alloc(LAUNCH_DATA_INTEGER);
		launch_data_set_integer(t, ai->ai_protocol);
		launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_PROTOCOL);
	}

	if (ai->ai_addr) {
		t = launch_data_alloc(LAUNCH_DATA_OPAQUE);
		launch_data_set_opaque(t, ai->ai_addr, ai->ai_addrlen);
		launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_ADDRESS);
	}

	if (ai->ai_canonname) {
		t = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(t, ai->ai_canonname);
		launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_CANONICALNAME);
	}

	t = launch_data_alloc(LAUNCH_DATA_FD);
	launch_data_set_fd(t, fd);
	launch_data_dict_insert(d, t, LAUNCH_JOBADDRINFOKEY_FD);

	return d;
}


static void sock_dict_cb(launch_data_t what, const char *key, void *context __attribute__((unused)))
{
	if (launch_data_get_type(what) == LAUNCH_DATA_DICTIONARY) {
		sock_dict_edit_entry(what, key);
	} else if (launch_data_get_type(what) == LAUNCH_DATA_ARRAY) {
		launch_data_t tmp;
		size_t i;

		for (i = 0; i < launch_data_array_get_count(what); i++) {
			tmp = launch_data_array_get_index(what, i);
			sock_dict_edit_entry(tmp, key);
		}
	}
}

static void sock_dict_edit_entry(launch_data_t tmp, const char *key)
{
	launch_data_t a, val;
	int sfd, st = SOCK_STREAM;
	bool passive = true;

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_TYPE))) {
		if (!strcasecmp(launch_data_get_string(val), "stream")) {
			st = SOCK_STREAM;
		} else if (!strcasecmp(launch_data_get_string(val), "dgram")) {
			st = SOCK_DGRAM;
		} else if (!strcasecmp(launch_data_get_string(val), "seqpacket")) {
			st = SOCK_SEQPACKET;
		}
	}

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PASSIVE)))
		passive = launch_data_get_bool(val);

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_SECUREWITHKEY))) {
		char secdir[sizeof(LAUNCH_SECDIR)], buf[1024];

		strcpy(secdir, LAUNCH_SECDIR);

		mkdtemp(secdir);

		sprintf(buf, "%s/%s", secdir, key);

		a = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(a, buf);
		launch_data_dict_insert(tmp, a, LAUNCH_JOBSOCKETKEY_PATHNAME);
	}
		
	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PATHNAME))) {
		struct sockaddr_un sun;

		memset(&sun, 0, sizeof(sun));

		sun.sun_family = AF_UNIX;

		strncpy(sun.sun_path, launch_data_get_string(val), sizeof(sun.sun_path));
	
		if ((sfd = _fd(socket(AF_UNIX, st, 0))) == -1)
			return;

		if (passive) {                  
			if (unlink(sun.sun_path) == -1 && errno != ENOENT) {
				close(sfd);     
				return;
			}
			if (bind(sfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
				close(sfd);
				return;
			}
			if ((st == SOCK_STREAM || st == SOCK_SEQPACKET)
					&& listen(sfd, SOMAXCONN) == -1) {
				close(sfd);
				return;
			}
		} else if (connect(sfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
			close(sfd);
			return;
		}

		val = launch_data_alloc(LAUNCH_DATA_FD);
		launch_data_set_fd(val, sfd);
		launch_data_dict_insert(tmp, val, LAUNCH_JOBSOCKETKEY_FD);
	} else {
		launch_data_t ai_array = launch_data_alloc(LAUNCH_DATA_ARRAY);
		const char *node = NULL, *serv = NULL;
		char servnbuf[50];
		struct addrinfo hints, *res0, *res;
		int gerr, sock_opt = 1;
		bool rendezvous = false;

		memset(&hints, 0, sizeof(hints));

		hints.ai_socktype = st;
		if (passive)
			hints.ai_flags |= AI_PASSIVE;

		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_NODENAME)))
			node = launch_data_get_string(val);
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_SERVICENAME))) {
			if (LAUNCH_DATA_INTEGER == launch_data_get_type(val)) {
				sprintf(servnbuf, "%lld", launch_data_get_integer(val));
				serv = servnbuf;
			} else {
				serv = launch_data_get_string(val);
			}
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_FAMILY))) {
			if (!strcasecmp("IPv4", launch_data_get_string(val)))
				hints.ai_family = AF_INET;
			else if (!strcasecmp("IPv6", launch_data_get_string(val)))
				hints.ai_family = AF_INET6;
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PROTOCOL))) {
			if (!strcasecmp("TCP", launch_data_get_string(val)))
				hints.ai_protocol = IPPROTO_TCP;
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_RENDEZVOUS))) {
			if (launch_data_get_bool(val))
				rendezvous = true;
		}

		if ((gerr = getaddrinfo(node, serv, &hints, &res0)) != 0) {
			fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(gerr));
			return;
		}

		for (res = res0; res; res = res->ai_next) {
			int rvs_fd = -1;
			if ((sfd = _fd(socket(res->ai_family, res->ai_socktype, res->ai_protocol))) == -1) {
				fprintf(stderr, "socket(): %s\n", strerror(errno));
				return;
			}
			if (hints.ai_flags & AI_PASSIVE) {
				if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt, sizeof(sock_opt)) == -1) {
					fprintf(stderr, "socket(): %s\n", strerror(errno));
					return;
				}
				if (bind(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					fprintf(stderr, "bind(): %s\n", strerror(errno));
					return;
				}
				if ((res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_SEQPACKET)
						&& listen(sfd, SOMAXCONN) == -1) {
					fprintf(stderr, "listen(): %s\n", strerror(errno));
					return;
				}
				if (rendezvous && (res->ai_family == AF_INET || res->ai_family == AF_INET6) &&
						(res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_DGRAM)) {
					DNSServiceRef service;
					DNSServiceErrorType error;
					char rvs_buf[200];
					short port;

					sprintf(rvs_buf, "_%s._%s.", serv, res->ai_socktype == SOCK_STREAM ? "tcp" : "udp");

					if (res->ai_family == AF_INET)
						port = ((struct sockaddr_in *)res->ai_addr)->sin_port;
					else
						port = ((struct sockaddr_in6 *)res->ai_addr)->sin6_port;

					error = DNSServiceRegister(&service, 0, 0, NULL, rvs_buf, NULL, NULL, port, 0, NULL, NULL, NULL);

					if (error == kDNSServiceErr_NoError) {
						rvs_fd = DNSServiceRefSockFD(service);
					} else {
						fprintf(stderr, "DNSServiceRegister(\"%s\"): %d\n", serv, error);
					}

				}
			} else {
				if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					fprintf(stderr, "connect(): %s\n", strerror(errno));
					return;
				}
			}
			val = create_launch_data_addrinfo_fd(res, sfd);
			if (rvs_fd != -1)
				launch_data_dict_insert(val, launch_data_new_fd(rvs_fd), LAUNCH_JOBSOCKETKEY_RENDEZVOUSFD);
			launch_data_array_set_index(ai_array, val, launch_data_array_get_count(ai_array));
		}
		launch_data_dict_insert(tmp, ai_array, LAUNCH_JOBSOCKETKEY_ADDRINFORESULTS);
	}
}

static CFPropertyListRef CreateMyPropertyListFromFile(const char *posixfile)
{
	CFPropertyListRef propertyList;
	CFStringRef       errorString;
	CFDataRef         resourceData;
	SInt32            errorCode;
	CFURLRef          fileURL;

	fileURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, posixfile, strlen(posixfile), false);
	if (!fileURL)
		fprintf(stderr, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed\n", getprogname(), posixfile);
	if (!CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, fileURL, &resourceData, NULL, NULL, &errorCode))
		fprintf(stderr, "%s: CFURLCreateDataAndPropertiesFromResource(%s) failed: %d\n", getprogname(), posixfile, (int)errorCode);
	propertyList = CFPropertyListCreateFromXMLData(kCFAllocatorDefault, resourceData, kCFPropertyListMutableContainers, &errorString);
	if (!propertyList)
		fprintf(stderr, "%s: propertyList is NULL\n", getprogname());

	return propertyList;
}

static void WriteMyPropertyListToFile(CFPropertyListRef plist, const char *posixfile)
{
	CFDataRef	resourceData;
	CFURLRef	fileURL;
	SInt32		errorCode;

	fileURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, posixfile, strlen(posixfile), false);
	if (!fileURL)
		fprintf(stderr, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed\n", getprogname(), posixfile);
	resourceData = CFPropertyListCreateXMLData(kCFAllocatorDefault, plist);
	if (resourceData == NULL)
		fprintf(stderr, "%s: CFPropertyListCreateXMLData(%s) failed", getprogname(), posixfile);
	if (!CFURLWriteDataAndPropertiesToResource(fileURL, resourceData, NULL, &errorCode))
		fprintf(stderr, "%s: CFURLWriteDataAndPropertiesToResource(%s) failed: %d\n", getprogname(), posixfile, (int)errorCode);
}

void myCFDictionaryApplyFunction(const void *key, const void *value, void *context)
{
	launch_data_t ik, iw, where = context;

	ik = CF2launch_data(key);
	iw = CF2launch_data(value);

	launch_data_dict_insert(where, iw, launch_data_get_string(ik));
	launch_data_free(ik);
}

static launch_data_t CF2launch_data(CFTypeRef cfr)
{
	launch_data_t r;
	CFTypeID cft = CFGetTypeID(cfr);

	if (cft == CFStringGetTypeID()) {
		char buf[4096];
		CFStringGetCString(cfr, buf, sizeof(buf), kCFStringEncodingUTF8);
		r = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(r, buf);
	} else if (cft == CFBooleanGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(r, CFBooleanGetValue(cfr));
	} else if (cft == CFArrayGetTypeID()) {
		CFIndex i, ac = CFArrayGetCount(cfr);
		r = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (i = 0; i < ac; i++) {
			CFTypeRef v = CFArrayGetValueAtIndex(cfr, i);
			if (v) {
				launch_data_t iv = CF2launch_data(v);
				launch_data_array_set_index(r, iv, i);
			}
		}
	} else if (cft == CFDictionaryGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		CFDictionaryApplyFunction(cfr, myCFDictionaryApplyFunction, r);
	} else if (cft == CFDataGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_ARRAY);
		launch_data_set_opaque(r, CFDataGetBytePtr(cfr), CFDataGetLength(cfr));
	} else if (cft == CFNumberGetTypeID()) {
		long long n;
		double d;
		CFNumberType cfnt = CFNumberGetType(cfr);
		switch (cfnt) {
		case kCFNumberSInt8Type:
		case kCFNumberSInt16Type:
		case kCFNumberSInt32Type:
		case kCFNumberSInt64Type:
		case kCFNumberCharType:
		case kCFNumberShortType:
		case kCFNumberIntType:
		case kCFNumberLongType:
		case kCFNumberLongLongType:
			CFNumberGetValue(cfr, kCFNumberLongLongType, &n);
			r = launch_data_alloc(LAUNCH_DATA_INTEGER);
			launch_data_set_integer(r, n);
			break;
		case kCFNumberFloat32Type:
		case kCFNumberFloat64Type:
		case kCFNumberFloatType:
		case kCFNumberDoubleType:
			CFNumberGetValue(cfr, kCFNumberDoubleType, &d);
			r = launch_data_alloc(LAUNCH_DATA_REAL);
			launch_data_set_real(r, d);
			break;
		default:
			r = NULL;
			break;
		}
	} else {
		r = NULL;
	}
	return r;
}

static int help_cmd(int argc, char *const argv[])
{
	FILE *where = stdout;
	int l, cmdwidth = 0;
	size_t i;
	
	if (argc == 0 || argv == NULL)
		where = stderr;

	fprintf(where, "usage: %s <subcommand>\n", getprogname());
	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++) {
		l = strlen(cmds[i].name);
		if (l > cmdwidth)
			cmdwidth = l;
	}
	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++)
		fprintf(where, "\t%-*s\t%s\n", cmdwidth, cmds[i].name, cmds[i].desc);

	return 0;
}

static int _fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}

static int load_and_unload_cmd(int argc, char *const argv[])
{
	int i, ch;
	bool wflag = false;
	bool lflag = false;

	if (!strcmp(argv[0], "load"))
		lflag = true;

	while ((ch = getopt(argc, argv, "w")) != -1) {
		switch (ch) {
		case 'w':
			wflag = true;
			break;
		default:
			fprintf(stderr, "usage: %s load [-w] paths...\n", getprogname());
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fprintf(stderr, "usage: %s load [-w] paths...\n", getprogname());
		return 1;
	}

	for (i = 0; i < argc; i++) {
		readcfg(argv[i], lflag, wflag);
		/* <rdar://problem/3956518> mDNSResponder needs to go native with launchd */
		if (!strcmp(argv[i], "/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist") && lflag)
			wait4path("/var/run/mDNSResponder");
	}

	return 0;
}

static int start_and_stop_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	const char *lmsgcmd = LAUNCH_KEY_STOPJOB;
	int e, r = 0;

	if (!strcmp(argv[0], "start"))
		lmsgcmd = LAUNCH_KEY_STARTJOB;

	if (argc != 2) {
		fprintf(stderr, "usage: %s %s <job label>\n", getprogname(), argv[0]);
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_dict_insert(msg, launch_data_new_string(argv[1]), lmsgcmd);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);
	return r;
}

static void print_jobs(launch_data_t j __attribute__((unused)), const char *label, void *context __attribute__((unused)))
{
	fprintf(stdout, "%s\n", label);
}

static int list_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	int ch, r = 0;
	bool vflag = false;

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			vflag = true;
			break;
		default:
			fprintf(stderr, "usage: %s list [-v]\n", getprogname());
			return 1;
		}
	}

	if (vflag) {
		fprintf(stderr, "usage: %s list: \"-v\" flag not implemented yet\n", getprogname());
		return 1;
	}

	msg = launch_data_new_string(LAUNCH_KEY_GETJOBS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_DICTIONARY) {
		launch_data_dict_iterate(resp, print_jobs, NULL);
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);

	return r;
}

static int stdio_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg, tmp;
	int e, fd = -1, r = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s %s <path>\n", getprogname(), argv[0]);
		return 1;
	}

	fd = open(argv[1], O_CREAT|O_APPEND|O_WRONLY, DEFFILEMODE);

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (fd == -1) {
		tmp = launch_data_new_string(argv[1]);
	} else {
		tmp = launch_data_new_fd(fd);
	}

	if (!strcmp(argv[0], "stdout")) {
		launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETSTDOUT);
	} else {
		launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETSTDERR);
	}

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	if (fd != -1)
		close(fd);

	launch_data_free(resp);

	return r;
}

static int fyi_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	const char *lmsgk = LAUNCH_KEY_RELOADTTYS;
	int e, r = 0;

	if (argc != 1) {
		fprintf(stderr, "usage: %s %s\n", getprogname(), argv[0]);
		return 1;
	}

	if (!strcmp(argv[0], "shutdown"))
		lmsgk = LAUNCH_KEY_SHUTDOWN;

	msg = launch_data_new_string(lmsgk);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);

	return r;
}

static int logupdate_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	int e, i, j, r = 0, m = 0;
	bool badargs = false, maskmode = false, onlymode = false, levelmode = false;
	const char *whichcmd = LAUNCH_KEY_SETLOGMASK;
	static const struct {
		const char *name;
		int level;
	} logtbl[] = {
		{ "debug",	LOG_DEBUG },
		{ "info",	LOG_INFO },
		{ "notice",	LOG_NOTICE },
		{ "warning",	LOG_WARNING },
		{ "error",	LOG_ERR },
		{ "critical",	LOG_CRIT },
		{ "alert",	LOG_ALERT },
		{ "emergency",	LOG_EMERG },
	};
	int logtblsz = sizeof logtbl / sizeof logtbl[0];

	if (argc >= 2) {
		if (!strcmp(argv[1], "mask"))
			maskmode = true;
		else if (!strcmp(argv[1], "only"))
			onlymode = true;
		else if (!strcmp(argv[1], "level"))
			levelmode = true;
		else
			badargs = true;
	}

	if (maskmode)
		m = LOG_UPTO(LOG_DEBUG);

	if (argc > 2 && (maskmode || onlymode)) {
		for (i = 2; i < argc; i++) {
			for (j = 0; j < logtblsz; j++) {
				if (!strcmp(argv[i], logtbl[j].name)) {
					if (maskmode)
						m &= ~(LOG_MASK(logtbl[j].level));
					else
						m |= LOG_MASK(logtbl[j].level);
					break;
				}
			}
			if (j == logtblsz) {
				badargs = true;
				break;
			}
		}
	} else if (argc > 2 && levelmode) {
		for (j = 0; j < logtblsz; j++) {
			if (!strcmp(argv[2], logtbl[j].name)) {
				m = LOG_UPTO(logtbl[j].level);
				break;
			}
		}
		if (j == logtblsz)
			badargs = true;
	} else if (argc == 1) {
		whichcmd = LAUNCH_KEY_GETLOGMASK;
	} else {
		badargs = true;
	}

	if (badargs) {
		fprintf(stderr, "usage: %s [[mask loglevels...] | [only loglevels...] [level loglevel]]\n", getprogname());
		return 1;
	}

	if (whichcmd == LAUNCH_KEY_SETLOGMASK) {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(msg, launch_data_new_integer(m), whichcmd);
	} else {
		msg = launch_data_new_string(whichcmd);
	}

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_INTEGER) {
		if (whichcmd == LAUNCH_KEY_GETLOGMASK) {
			m = launch_data_get_integer(resp);
			for (j = 0; j < logtblsz; j++) {
				if (m & LOG_MASK(logtbl[j].level))
					fprintf(stdout, "%s ", logtbl[j].name);
			}
			fprintf(stdout, "\n");
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);

	return r;
}

static int limit_cmd(int argc __attribute__((unused)), char *const argv[])
{
	char slimstr[100];
	char hlimstr[100];
	struct rlimit *lmts = NULL;
	launch_data_t resp, resp1 = NULL, msg, tmp;
	int r = 0;
	size_t i, lsz = -1, which = 0;
	rlim_t slim = -1, hlim = -1;
	bool badargs = false;
	static const struct {
		const char *name;
		int lim;
	} limlookup[] = {
		{ "cpu",	RLIMIT_CPU },
		{ "filesize",	RLIMIT_FSIZE },
		{ "data",	RLIMIT_DATA },
		{ "stack",	RLIMIT_STACK },
		{ "core",	RLIMIT_CORE },
		{ "rss", 	RLIMIT_RSS },
		{ "memlock",	RLIMIT_MEMLOCK },
		{ "maxproc",	RLIMIT_NPROC },
		{ "maxfiles",	RLIMIT_NOFILE }
	};
	size_t limlookupcnt = sizeof limlookup / sizeof limlookup[0];
	bool name2num(const char *n) {
		for (i = 0; i < limlookupcnt; i++) {
			if (!strcmp(limlookup[i].name, n)) {
				which = limlookup[i].lim;
				return false;
			}
		}
		return true;
	};
	const char *num2name(int n) {
		for (i = 0; i < limlookupcnt; i++) {
			if (limlookup[i].lim == n)
				return limlookup[i].name;
		}
		return NULL;
	};
	const char *lim2str(rlim_t val, char *buf) {
		if (val == RLIM_INFINITY)
			strcpy(buf, "unlimited");
		else
			sprintf(buf, "%lld", val);
		return buf;
	};
	bool str2lim(const char *buf, rlim_t *res) {
		char *endptr;
		*res = strtoll(buf, &endptr, 10);
		if (!strcmp(buf, "unlimited")) {
			*res = RLIM_INFINITY;
			return false;
		} else if (*endptr == '\0') {
			 return false;
		}
		return true;
	};

	if (argc > 4)
		badargs = true;

	if (argc >= 3 && str2lim(argv[2], &slim))
		badargs = true;
	else
		hlim = slim;

	if (argc == 4 && str2lim(argv[3], &hlim))
		badargs = true;

	if (argc >= 2 && name2num(argv[1]))
		badargs = true;

	if (badargs) {
		fprintf(stderr, "usage: %s %s [", getprogname(), argv[0]);
		for (i = 0; i < limlookupcnt; i++)
			fprintf(stderr, "%s %s", limlookup[i].name, (i + 1) == limlookupcnt ? "" : "| ");
		fprintf(stderr, "[both | soft hard]]\n");
		return 1;
	}

	msg = launch_data_new_string(LAUNCH_KEY_GETRESOURCELIMITS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_OPAQUE) {
		lmts = launch_data_get_opaque(resp);
		lsz = launch_data_get_opaque_size(resp);
		if (argc <= 2) {
			for (i = 0; i < (lsz / sizeof(struct rlimit)); i++) {
				if (argc == 2 && which != i)
					continue;
				fprintf(stdout, "\t%-12s%-15s%-15s\n", num2name(i),
						lim2str(lmts[i].rlim_cur, slimstr),
						lim2str(lmts[i].rlim_max, hlimstr));
			}
		}
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], launch_data_get_string(resp));
		r = 1;
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	if (argc <= 2 || r != 0) {
		launch_data_free(resp);
		return r;
	} else {
		resp1 = resp;
	}

	lmts[which].rlim_cur = slim;
	lmts[which].rlim_max = hlim;

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_new_opaque(lmts, lsz);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETRESOURCELIMITS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], launch_data_get_string(resp));
		r = 1;
	} else if (launch_data_get_type(resp) != LAUNCH_DATA_OPAQUE) {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);
	launch_data_free(resp1);

	return r;
}

static int umask_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	bool badargs = false;
	char *endptr;
	long m = 0;
	int r = 0;

	if (argc == 2) {
		m = strtol(argv[1], &endptr, 8);
		if (*endptr != '\0' || m > 0777)
			badargs = true;
	}

	if (argc > 2 || badargs) {
		fprintf(stderr, "usage: %s %s <mask>\n", getprogname(), argv[0]);
		return 1;
	}


	if (argc == 1) {
		msg = launch_data_new_string(LAUNCH_KEY_GETUMASK);
	} else {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(msg, launch_data_new_integer(m), LAUNCH_KEY_SETUMASK);
	}
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), argv[0], launch_data_get_string(resp));
		r = 1;
	} else if (launch_data_get_type(resp) != LAUNCH_DATA_INTEGER) {
		fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
		r = 1;
	} else if (argc == 1) {
		fprintf(stdout, "%o\n", (unsigned int)launch_data_get_integer(resp));
	}

	launch_data_free(resp);

	return r;
}

/* <rdar://problem/3956518> mDNSResponder needs to go native with launchd */
static void wait4path(const char *path)
{
	struct timespec timeout = { 1, 0 };
	int r, kq = kqueue();
	int thedir = open(dirname(path), O_EVTONLY);
	struct kevent kev;
	struct stat sb;

	if (thedir == -1)
		goto out;

	EV_SET(&kev, thedir, EVFILT_VNODE, EV_ADD, NOTE_WRITE, 0, 0);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		fprintf(stderr, "adding EVFILT_VNODE to kqueue failed: %s\n", strerror(errno));
		goto out;
	}

	for (;;) {
		if (stat(path, &sb) == 0)
			goto out;
		r = kevent(kq, NULL, 0, &kev, 1, &timeout);
		if (r == -1) {
			fprintf(stderr, "kevent(): %s\n", strerror(errno));
			goto out;
		} else if (r == 0) {
			fprintf(stderr, "Gave up waiting for %s to show up!\n", path);
			goto out;
		}
	}
out:
	if (thedir != -1)
		close(thedir);
	if (kq != -1)
		close(kq);
}
