#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>

#include "launch.h"

#define LAUNCH_SECDIR "/tmp/launch-XXXXXX"

static void distill_config_file(launch_data_t);
static void sock_dict_cb(launch_data_t what, const char *key, void *context);
static void sock_dict_edit_entry(launch_data_t tmp, const char *key);
static launch_data_t CF2launch_data(CFTypeRef);
static CFPropertyListRef CreateMyPropertyListFromFile(const char *);
static void WriteMyPropertyListToFile(CFPropertyListRef, const char *);
static void usage(FILE *) __attribute__((noreturn));
static void readcfg(const char *, bool load, bool editondisk);
static void get_launchd_env(void);
static void set_launchd_env(char *);
static void unset_launchd_env(char *);
static void set_launchd_envkv(char *, char *);
static void update_plist(CFPropertyListRef, const char *, bool);
static int _fd(int);

int main(int argc, char *argv[])
{
	int ch;
	bool wflag = false, lflag = true;
	char *what = NULL;

	while ((ch = getopt(argc, argv, "U:ES:hl:u:w")) != -1) {
		switch (ch) {
		case 'U':
			unset_launchd_env(optarg);
			break;
		case 'E':
			get_launchd_env();
			break;
		case 'S':
			set_launchd_env(optarg);
			break;
		case 'w':
			wflag = true;
			break;
		case 'l':
			what = optarg;
			break;
		case 'u':
			what = optarg;
			lflag = false;
			break;
		case 'h':
			usage(stdout);
			break;
		case '?':
		default:
			usage(stderr);
			break;
		}
	}

	readcfg(what, lflag, wflag);

	exit(EXIT_SUCCESS);
}

static void print_launchd_env(launch_data_t obj, const char *key, void *context)
{
	if (context)
		fprintf(stdout, "setenv %s %s;\n", key, launch_data_get_string(obj));
	else
		fprintf(stdout, "%s=%s; export %s;\n", key, launch_data_get_string(obj), key);
}

static void unset_launchd_env(char *arg)
{
	launch_data_t resp, tmp, req = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmp = launch_data_alloc(LAUNCH_DATA_STRING);
	launch_data_set_string(tmp, arg);
	launch_data_dict_insert(req, tmp, LAUNCH_KEY_UNSETUSERENVIRONMENT);

	resp = launch_msg(req);

	launch_data_free(req);

	if (resp) {
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"" LAUNCH_KEY_UNSETUSERENVIRONMENT "\"): %s\n", strerror(errno));
	}
}

static void set_launchd_env(char *arg)
{
	char *key = arg, *val = strchr(arg, '=');

	if (val) {
		*val = '\0';
		val++;
	} else
		val = "";

	set_launchd_envkv(key, val);
}

static void set_launchd_envkv(char *key, char *val)
{
	launch_data_t resp, tmp, tmpv, req = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmpv = launch_data_alloc(LAUNCH_DATA_STRING);
	launch_data_set_string(tmpv, val);
	launch_data_dict_insert(tmp, tmpv, key);
	launch_data_dict_insert(req, tmp, LAUNCH_KEY_SETUSERENVIRONMENT);

	resp = launch_msg(req);

	launch_data_free(req);

	if (resp) {
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"" LAUNCH_KEY_SETUSERENVIRONMENT "\"): %s\n", strerror(errno));
	}
}

static void get_launchd_env(void)
{
	launch_data_t resp, req = launch_data_alloc(LAUNCH_DATA_STRING);
	char *s = getenv("SHELL");

	launch_data_set_string(req, LAUNCH_KEY_GETUSERENVIRONMENT);

	resp = launch_msg(req);

	if (resp) {
		launch_data_dict_iterate(resp, print_launchd_env, s ? strstr(s, "csh") : NULL);
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"" LAUNCH_KEY_GETUSERENVIRONMENT "\"): %s\n", strerror(errno));
	}
}

static void unloadjob(launch_data_t job)
{
	launch_data_t resp, tmp, tmps, msg;

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_alloc(LAUNCH_DATA_STRING);
	tmps = launch_data_dict_lookup(job, LAUNCH_JOBKEY_LABEL);
	launch_data_set_string(tmp, launch_data_get_string(tmps));
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_REMOVEJOB);
	resp = launch_msg(msg);
	launch_data_free(msg);
	if (LAUNCH_DATA_STRING == launch_data_get_type(resp)) {
		if (strcmp(LAUNCH_RESPONSE_SUCCESS, launch_data_get_string(resp)))
			fprintf(stderr, "%s\n", launch_data_get_string(resp));
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
	CFPropertyListRef plist;
	DIR *d;
	struct dirent *de;
	struct stat sb;
	char *foo;
	bool job_disabled;
	launch_data_t resp, msg, tmp, tmpe, tmpd, tmpa, id_plist;

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
		launch_data_dict_insert(msg, tmpa, LAUNCH_KEY_SUBMITJOBS);
	}

	resp = launch_msg(msg);

	if (resp) {
		if (LAUNCH_DATA_STRING == launch_data_get_type(resp)) {
			if (strcmp(LAUNCH_RESPONSE_SUCCESS, launch_data_get_string(resp)))
				fprintf(stderr, "%s\n", launch_data_get_string(resp));
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

		if ((gerr = getaddrinfo(node, serv, &hints, &res0)) != 0) {
			fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(gerr));
			return;
		}

		for (res = res0; res; res = res->ai_next) {
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
			} else {
				if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					fprintf(stderr, "connect(): %s\n", strerror(errno));
					return;
				}
			}
			val = create_launch_data_addrinfo_fd(res, sfd);
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

static void usage(FILE *where)
{
	fprintf(where, "usage: %s\n", getprogname());
	fprintf(where, "\t-w Write to the service. Updates the Disabled boolean.\n");
	fprintf(where, "\t-l <xmlfile>\tLoad a given service.\n");
	fprintf(where, "\t-u <xmlfile>\tUnload a given service.\n");
	fprintf(where, "\t-S FOO=bar\tSet per-user environmental variable 'FOO' to value 'bar'.\n");
	fprintf(where, "\t-U FOO\t\tUnset per-user environmental variable 'FOO'.\n");
	fprintf(where, "\t-E\t\tGet the per-user environmental variables.\n");
	fprintf(where, "\t-h\t\tThis help statement.\n");
	if (where == stdout)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}

static int _fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}
