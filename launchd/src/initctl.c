#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>

#include "libinitng.h"

static const char *argv0 = NULL;

static void handleConfigFile(const char *file);
static CFPropertyListRef CreateMyPropertyListFromFile(const char *posixfile);
static void myEnvpCallback(const void *key, const void *value, char **where);

int main(int argc, char *argv[])
{
	DIR *d;
	struct dirent *de;
	struct stat sb;

	initng_init();

	argv0 = argv[0];

	if (argc != 2) {
		fprintf(stderr, "usage: %s: <configdir|configfile>\n", argv0);
		exit(EXIT_FAILURE);
	}

	stat(argv[1], &sb);

	if (S_ISREG(sb.st_mode)) {
		handleConfigFile(argv[1]);
		exit(EXIT_SUCCESS);
	}

	if ((d = opendir(argv[1])) == NULL) {
		fprintf(stderr, "%s: opendir() failed to open the directory\n", argv0);
		exit(EXIT_FAILURE);
	}

	while ((de = readdir(d)) != NULL) {
		if ((de->d_name[0] != '.')) {
			char *foo;
			if (asprintf(&foo, "%s/%s", argv[1], de->d_name))
				handleConfigFile(foo);
			free(foo);
		}
	}

	exit(EXIT_SUCCESS);
}

static void handleConfigFile(const char *file)
{
	initng_jobinfo_t j = NULL;
	CFPropertyListRef plist = CreateMyPropertyListFromFile(file);
	char buf[4096];

	if (!plist) {
		fprintf(stderr, "%s: no plist was returned for: %s\n", argv0, file);
		return;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("UUID"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("UUID"));
		CFUUIDRef u;
		union {
			CFUUIDBytes b;
			char	rawuuid[16];
		} uu;
		if (!v) goto out;
		u = CFUUIDCreateFromString(NULL, v);
		if (!u) goto out;
		uu.b = CFUUIDGetUUIDBytes(u);
		if (!initng_jobinfo_alloc(&j, uu.rawuuid)) goto out;
		CFRelease(u);
	}
	if (CFDictionaryContainsKey(plist, CFSTR("UserName"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("UserName"));
		if (!v) goto out;
		CFStringGetCString(v, buf, sizeof(buf), kCFStringEncodingUTF8);
		if (!initng_jobinfo_set_UserName(j, buf)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("GroupName"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("GroupName"));
		if (!v) goto out;
		CFStringGetCString(v, buf, sizeof(buf), kCFStringEncodingUTF8);
		if (!initng_jobinfo_set_GroupName(j, buf)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("inetdSingleThreaded"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("inetdSingleThreaded"));
		if (!v || !initng_jobinfo_set_inetdSingleThreaded(j, CFBooleanGetValue(v))) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("LaunchOnce"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("LaunchOnce"));
		if (!v || !initng_jobinfo_set_LaunchOnce(j, CFBooleanGetValue(v))) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("OnDemand"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("OnDemand"));
		if (!v || !initng_jobinfo_set_OnDemand(j, CFBooleanGetValue(v))) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("Batch"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("Batch"));
		if (!v || !initng_jobinfo_set_Batch(j, CFBooleanGetValue(v))) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("ServiceIPC"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("ServiceIPC"));
		if (!v || !initng_jobinfo_set_ServiceIPC(j, CFBooleanGetValue(v))) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("PeriodicSeconds"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("PeriodicSeconds"));
		unsigned int tmp = 0;
		if (!v) goto out;
		CFNumberGetValue(v, kCFNumberIntType, &tmp);
	       	if (!initng_jobinfo_set_PeriodicSeconds(j, tmp)) goto out;
	}
#if 0
	if (CFDictionaryContainsKey(plist, CFSTR("SpecificTimeval"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("SpecificTimeval"));
		unsigned int tmp = 0;
		if (!v) goto out;
		CFNumberGetValue(v, kCFNumberIntType, &tmp);
	       	if (!initng_jobinfo_set_SpecificTimeval(j, (time_t)tmp)) goto out;
	}
#endif
	if (CFDictionaryContainsKey(plist, CFSTR("Program"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("Program"));
		if (!v) goto out;
		CFStringGetCString(v, buf, sizeof(buf), kCFStringEncodingUTF8);
	       	if (!initng_jobinfo_set_Program(j, buf)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("ProgramArguments"))) {
		CFIndex count;
		char **tmp;
		int ti;
		const void *v = CFDictionaryGetValue(plist, CFSTR("ProgramArguments"));
		if (!v) goto out;
		count = CFArrayGetCount(v);
		tmp = malloc((count + 1) * sizeof(char*));
		tmp[count] = NULL;
		for (ti = 0; ti < count; ti++) {
			const void *tv = CFArrayGetValueAtIndex(v, ti);
			if (!tv) goto out;
			CFStringGetCString(tv, buf, sizeof(buf), kCFStringEncodingUTF8);
			tmp[ti] = strdup(buf);
		}
		if (!initng_jobinfo_set_ProgramArguments(j, tmp)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("EnvironmentVariables"))) {
		CFIndex count;
		char **tmp;
		const void *v = CFDictionaryGetValue(plist, CFSTR("EnvironmentVariables"));
		if (!v) goto out;
		count = CFDictionaryGetCount(v);
		tmp = calloc(1, (count + 1) * sizeof(char*));
		CFDictionaryApplyFunction(v, (CFDictionaryApplierFunction)myEnvpCallback, tmp);
		if (!initng_jobinfo_set_EnvironmentVariables(j, tmp)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("ServiceDescription"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("ServiceDescription"));
		if (!v) goto out;
		CFStringGetCString(v, buf, sizeof(buf), kCFStringEncodingUTF8);
	       	if (!initng_jobinfo_set_ServiceDescription(j, buf)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("MachServiceNames"))) {
		CFIndex count;
		char **tmp;
		int ti;
		const void *v = CFDictionaryGetValue(plist, CFSTR("MachServiceNames"));
		if (!v) goto out;
		count = CFArrayGetCount(v);
		tmp = malloc((count + 1) * sizeof(char*));
		tmp[count] = NULL;
		for (ti = 0; ti < count; ti++) {
			const void *tv = CFArrayGetValueAtIndex(v, ti);
			if (!tv) goto out;
			CFStringGetCString(tv, buf, sizeof(buf), kCFStringEncodingUTF8);
			tmp[ti] = strdup(buf);
		}
		if (!initng_jobinfo_set_MachServiceNames(j, tmp)) goto out;
	}
	if (CFDictionaryContainsKey(plist, CFSTR("Sockets"))) {
		CFIndex count;
		const void *v = CFDictionaryGetValue(plist, CFSTR("Sockets"));
		int ti = 0;
		if (!v) goto out;
		count = CFArrayGetCount(v);
		for (ti = 0; ti < count; ti++) {
			struct addrinfopp tmp;
			const void *tv = CFArrayGetValueAtIndex(v, ti);
			if (!tv) goto out;
			memset(&tmp, 0, sizeof(struct addrinfopp));
			if (CFDictionaryContainsKey(tv, CFSTR("addrinfo_nodename"))) {
				const void *iv = CFDictionaryGetValue(tv, CFSTR("addrinfo_nodename"));
				if (!iv) goto out;
				CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
				strncpy(tmp.nodename, buf, sizeof(tmp.nodename));
			}
			if (CFDictionaryContainsKey(tv, CFSTR("addrinfo_servname"))) {
				const void *iv = CFDictionaryGetValue(tv, CFSTR("addrinfo_servname"));
				if (!iv) goto out;
				CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
				strncpy(tmp.servname, buf, sizeof(tmp.servname));
			}
			if (CFDictionaryContainsKey(tv, CFSTR("addrinfo_passive"))) {
				const void *iv = CFDictionaryGetValue(tv, CFSTR("addrinfo_passive"));
				if (!iv) goto out;
				if (CFBooleanGetValue(iv))
					tmp.hints.ai_flags |= AI_PASSIVE;
			}
			if (CFDictionaryContainsKey(tv, CFSTR("addrinfo_socktype"))) {
				const void *iv = CFDictionaryGetValue(tv, CFSTR("addrinfo_socktype"));
				if (!iv) goto out;
				CFStringGetCString(iv, buf, sizeof(buf), kCFStringEncodingUTF8);
				if (!strcmp(buf, "SOCK_STREAM"))
					tmp.hints.ai_socktype = SOCK_STREAM;
				else if (!strcmp(buf, "SOCK_DGRAM"))
					tmp.hints.ai_socktype = SOCK_DGRAM;
			}
			if (!initng_jobinfo_add_Socket(j, &tmp)) {
				fprintf(stdout, "%s: failed to add a socket\n", argv0);
				goto out;
			}
		}
	}
	if (CFDictionaryContainsKey(plist, CFSTR("Disabled"))) {
		const void *v = CFDictionaryGetValue(plist, CFSTR("Disabled"));
		if (!v || !initng_jobinfo_set_Enabled(j, !CFBooleanGetValue(v))) goto out;
	} else {
		if (!initng_jobinfo_set_Enabled(j, true))
			goto out;
	}


	goto out_good;
out:
	fprintf(stdout, "%s: failed to register: %s\n", argv0, file);
out_good:
	CFRelease(plist);
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
	CFRelease(resourceData);

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
