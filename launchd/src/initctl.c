#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>

#define INITNG_PRIVATE_API
#include "libinitng.h"

static int thefd = 0;
static const char *argv0 = NULL;

static void handleConfigFile(const char *file);
static CFPropertyListRef CreateMyPropertyListFromFile(const char *posixfile);
static void myEnvpCallback(const void *key, const void *value, char **where);
static void usage(FILE *where) __attribute__((noreturn));
static void loadcfg(char *what);
static void monitor_initngd(void);
static void removeJob(char *joblabel);

int main(int argc, char *argv[])
{
	int ch;

	if ((thefd = initng_open()) == -1) {
		fprintf(stderr, "initng_open(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	argv0 = argv[0];

	while ((ch = getopt(argc, argv, "mhl:r:")) != -1) {
		switch (ch) {
		case 'm':
			monitor_initngd();
			break;
		case 'l':
			loadcfg(optarg);
			break;
		case 'r':
			removeJob(optarg);
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
	argc -= optind;
	argv += optind;

	initng_close(thefd);

	exit(EXIT_SUCCESS);
}

static void mon_cb(int fd __attribute__((unused)), char *command, char *data[], void *cookie __attribute__((unused)), initng_cred_t *cred __attribute__((unused)))
{
	int sfd;

	if (!strcmp(command, "addFD")) {
		sfd = strtol(data[2], NULL, 10);
		close(sfd);
	}

	fprintf(stdout, "%s\n", command);
	for (; *data; data++)
		fprintf(stdout, "\t%s\n", *data);

}

static void monitor_initngd(void)
{
	if (initng_msg(thefd, "enableMonitor", "true", NULL) == -1) {
		fprintf(stderr, "monitoring request failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (;;) {
		if (initng_recvmsg(thefd, mon_cb, NULL) == -1)
			break;
	}
	exit(EXIT_FAILURE);
}

static void removeJob(char *joblabel)
{
	if (initng_msg(thefd, "removeJob", joblabel, NULL) == -1) {
		fprintf(stderr, "removeJob failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void loadcfg(char *what)
{
	DIR *d;
	struct dirent *de;
	struct stat sb;

	stat(what, &sb);

	if (S_ISREG(sb.st_mode)) {
		handleConfigFile(what);
	} else {
		if ((d = opendir(what)) == NULL) {
			fprintf(stderr, "%s: opendir() failed to open the directory\n", argv0);
			exit(EXIT_FAILURE);
		}

		while ((de = readdir(d)) != NULL) {
			if ((de->d_name[0] != '.')) {
				char *foo;
				if (asprintf(&foo, "%s/%s", what, de->d_name))
					handleConfigFile(foo);
				free(foo);
			}
		}

		closedir(d);
	}
}

static char **getflag(const void *cfval)
{
	char **tmp = malloc(sizeof(char*) * 3);

	tmp[0] = NULL;
	if (CFBooleanGetValue(cfval))
		tmp[1] = strdup("true");
	else
		tmp[1] = strdup("false");
	tmp[2] = NULL;

	return tmp;
}

static char **getcfstring(const void *cfval)
{
	char buf[4096];
	char **tmp = malloc(sizeof(char*) * 3);
	
	CFStringGetCString(cfval, buf, sizeof(buf), kCFStringEncodingUTF8);
	tmp[0] = NULL;
	tmp[1] = strdup(buf);
	tmp[2] = NULL;

	return tmp;
}

static char **getcfstringarray(const void *cfval)
{
	char buf[4096];
	const void *tv;
	CFIndex count;
	char **tmp;
	int ti;

	count = CFArrayGetCount(cfval);
	tmp = calloc(1, (count + 2) * sizeof(char*));
	for (ti = 0; ti < count; ti++) {
		if (!(tv = CFArrayGetValueAtIndex(cfval, ti)))
			goto out_bad;
		CFStringGetCString(tv, buf, sizeof(buf), kCFStringEncodingUTF8);
		tmp[ti + 1] = strdup(buf);
	}
	return tmp;
out_bad:
	/* we could be a little more clever here, do it later */
	for (ti = 1; ti < (count + 1); ti++) {
		if (tmp[ti])
			free(tmp[ti]);
	}
	free(tmp);
	return NULL;
}

static char **getcfstringenv(const void *cfval)
{
	char **tmp;
	CFIndex count;

	count = CFDictionaryGetCount(cfval);
	tmp = calloc(1, (count + 2) * sizeof(char*));
	CFDictionaryApplyFunction(cfval, (CFDictionaryApplierFunction)myEnvpCallback, tmp + 1);

	return tmp;
}

static struct cf_file_option {
	const char *cfkey;
	char *command;
	char ** (*func)(const void *cfval);
} cf_file_options[] = {
	{ "inetdSingleThreaded", "setInetdSingleThreaded", getflag },
	{ "UserName", "setUserName", getcfstring },
	{ "GroupName", "setGroupName", getcfstring },
	{ "Program", "setProgram", getcfstring },
	{ "Umask", "setUmask", getcfstring },
	{ "ServiceDescription", "setServiceDescription", getcfstring },
	{ "ProgramArguments", "setProgramArguments", getcfstringarray },
	{ "EnvironmentVariables", "setEnvironmentVariables", getcfstringenv },
	{ "MachServiceNames", "setMachServiceNames", getcfstringarray },
};

static void handleConfigFile(const char *file)
{
	CFPropertyListRef plist = CreateMyPropertyListFromFile(file);
	char buf[4096];
	char *joblabel = NULL;
	size_t i;
	const void *v, *tv, *iv;
	char **msga, **msgatmp;
	CFIndex count;
	int ti = 0;
	bool e = true;

	if (!plist) {
		fprintf(stderr, "%s: no plist was returned for: %s\n", argv0, file);
		return;
	}
	if (!CFDictionaryContainsKey(plist, CFSTR("Label")))
		return;
	if (!(v = CFDictionaryGetValue(plist, CFSTR("Label"))))
		return;
	CFStringGetCString(v, buf, sizeof(buf), kCFStringEncodingUTF8);
	joblabel = strdup(buf);
	if (initng_msg(thefd, "createJob", joblabel, NULL) == -1) {
		fprintf(stderr, "createJob failed: %s\n", strerror(errno));
		return;
	}

	for (i = 0; i < (sizeof(cf_file_options) / sizeof(struct cf_file_option)); i++) {
		CFStringRef sr = CFStringCreateWithCString(NULL, cf_file_options[i].cfkey, kCFStringEncodingUTF8);
		if (!CFDictionaryContainsKey(plist, sr)) {
			continue;
		}
		if (!(v = CFDictionaryGetValue(plist, sr))) {
			fprintf(stderr, "key \"%s\" without value?!? skipping...\n", cf_file_options[i].cfkey);
			continue;
		}
		msga = cf_file_options[i].func(v);
		if (msga) {
			msga[0] = joblabel;
			if (initng_msga(thefd, cf_file_options[i].command, msga) == -1) {
				fprintf(stderr, "%s failed: %s\n", cf_file_options[i].command, strerror(errno));
				return;
			}
			for (msgatmp = msga + 1; *msgatmp; msgatmp++)
				free(*msgatmp);
			free(msga);
		} else {
			fprintf(stderr, "no msga!?!\n");
			return;
		}
	}

	if (!CFDictionaryContainsKey(plist, CFSTR("Sockets")))
		return;
	if (!(v = CFDictionaryGetValue(plist, CFSTR("Sockets"))))
		return;

	count = CFArrayGetCount(v);
	for (ti = 0; ti < count; ti++) {
		char socklabel[1024] = { 0 };
		char socknodename[1024] = { 0 };
		char sockservname[1024] = { 0 };
		char sockpathname[1024] = { 0 };
		char sockfamily[1024] = { 0 };
		char socktype[1024] = { 0 };
		char sockprotocol[1024] = { 0 };
		char sockpassive[1024] = { 'f', 'a', 'l', 's', 'e', 0 };
		if (!(tv = CFArrayGetValueAtIndex(v, ti))) {
			fprintf(stderr, "failed to get Socket %d\n", ti);
			break;
		}
		if (!CFDictionaryContainsKey(tv, CFSTR("SockLabel")))
			goto socket_out;
		if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockLabel"))))
			goto socket_out;
		CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
		strcpy(socklabel, buf);

		if (CFDictionaryContainsKey(tv, CFSTR("SockPathName"))) {
			if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockPathName"))))
				goto socket_out;
			CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
			strcpy(sockpathname, buf);

			if (!CFDictionaryContainsKey(tv, CFSTR("SockType")))
				goto socket_out;
			if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockType"))))
				goto socket_out;
			CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
			strcpy(socktype, buf);
		} else {
			if (CFDictionaryContainsKey(tv, CFSTR("SockNodeName"))) {
				if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockNodeName"))))
					goto socket_out;
				CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
				strcpy(socknodename, buf);
			}

			if (!CFDictionaryContainsKey(tv, CFSTR("SockServiceName")))
				goto socket_out;
			if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockServiceName"))))
				goto socket_out;
			CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
			strcpy(sockservname, buf);

			if (CFDictionaryContainsKey(tv, CFSTR("SockFamily"))) {
				if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockFamily"))))
					goto socket_out;
				CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
				strcpy(sockfamily, buf);
			}

			if (CFDictionaryContainsKey(tv, CFSTR("SockType"))) {
				if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockType"))))
					goto socket_out;
				CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
				strcpy(socktype, buf);
			}
		}

		if (CFDictionaryContainsKey(tv, CFSTR("SockProtocol"))) {
			if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockProtocol"))))
				goto socket_out;
			CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
			strcpy(sockprotocol, buf);
		}

		if (CFDictionaryContainsKey(tv, CFSTR("SockPassive"))) {
			if (!(iv = CFDictionaryGetValue(tv, CFSTR("SockPassive"))))
				goto socket_out;
			if (CFBooleanGetValue(iv))
				strcpy(sockpassive, "true");
		}

		if (strlen(sockpathname) > 0) {
			if (initng_msg(thefd, "addUnixSocket", joblabel, socklabel, sockpathname,
					 socktype, sockprotocol, sockpassive, NULL) == -1) {
				fprintf(stderr, "addUnixSocket failed: %s\n", strerror(errno));
				return;
			}
		} else {
			if (initng_msg(thefd, "addGetaddrinfoSockets", joblabel, socklabel, socknodename, sockservname,
					sockfamily, socktype, sockprotocol, sockpassive, NULL) == -1) {
				fprintf(stderr, "addGetaddrinfoSockets failed: %s\n", strerror(errno));
				return;
			}
		}

		continue;
socket_out:
		fprintf(stderr, "failed to add Socket at index %d\n", ti);
		return;
	}

	if (CFDictionaryContainsKey(plist, CFSTR("Disabled"))) {
		if ((v = CFDictionaryGetValue(plist, CFSTR("Disabled"))))
			e = !CFBooleanGetValue(v);
	}
	if (initng_msg(thefd, "enableJob", joblabel, e ? "true" : "false", NULL) == -1)
		fprintf(stderr, "enableJob failed: %s\n", strerror(errno));
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
		fprintf(stderr, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed\n", argv0, posixfile);
	if (!CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, fileURL, &resourceData, NULL, NULL, &errorCode))
		fprintf(stderr, "%s: CFURLCreateDataAndPropertiesFromResource(%s) failed: %d\n", argv0, posixfile, (int)errorCode);
	propertyList = CFPropertyListCreateFromXMLData(kCFAllocatorDefault, resourceData, kCFPropertyListImmutable, &errorString);
	if (!propertyList)
		fprintf(stderr, "%s: propertyList is NULL\n", argv0);

	return propertyList;
}

static void myEnvpCallback(const void *key, const void *value, char **where)
{
	char buf[4096];
	int i = 0;
	char **tmp;
	for (tmp = where; *tmp; tmp++);
	CFStringGetCString(key, buf, sizeof(buf), kCFStringEncodingUTF8);
	i = strlen(buf);
	buf[i] = '=';
	CFStringGetCString(value, buf + i + 1, sizeof(buf) - (i + 1), kCFStringEncodingUTF8);
	*tmp = strdup(buf);
}

static void usage(FILE *where)
{
	if (where == stdout)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}
