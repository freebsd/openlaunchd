/**
 * SafeBootPrivate.c - Resources for SafeBoot
 * gary f giusti | giusti@apple.com
 * $Apple$
 **
 * Copyright (c) 1999-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").	You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 **
 * Provides access to the BOM private framework.
 *
 * WARNING: This code uses private BOM API.  Private API is
 * subject to change at any time without notice, and it's use by
 * parties unknown to the Core Graphics authors is in no way supported.
 * If you borrow code from here for other use and it later breaks, you
 * have no basis for complaint.
 **/

#include <Bom/Bom.h>
#include "Log.h"
#include "main.h"

#define	kBaseSystemPath		"/System/Library/CoreServices/BaseSystem.bom"
#define	kSystemItemsPath	"./System/Library/StartupItems"
#define kBundleDirectory	"/System/Library/CoreServices/SystemStarter"
#define kBundleExtension	"bundle"


typedef struct _Private_SafeBootContext {

	CFMutableArrayRef			aBOMList;

} *SafeBootContext;

#define _SafeBoot_C_
#include "SafeBoot.h"


/*
	If we're Safe Booting, see if we have BOM resources to use. If so create a list of "Safe" StartupItems.
	All StartupItems that come with the base system are considered Safe, all others are considered not Safe.
	If there is any kind of error or list is no items, context will return NULL and SystemStarter will
	start everything in /System/Library/StartupItems
*/
SafeBootContext InitSafeBoot()
{
	BOMBom				aBOM     = NULL;
	BOMFSObject			aBOMPath = NULL;
	BOMBomEnumerator	aBOMEnumerator	= NULL;
	BOMFSObject			aEnumStep	= NULL;
	SafeBootContext 	aContext = (SafeBootContext)malloc(sizeof(struct _Private_SafeBootContext));

	if (NULL == aContext) {
	  	if (gDebugFlag) {
		  error(CFSTR("Initializing SafeBoot bundle error: could not allocate bundle context data.\n"));
		}
		return (NULL);
	}

	aContext->aBOMList	= CFArrayCreateMutable(NULL, 24, NULL);		/* 21 current safe + a few extra */

	aBOM = BOMBomNewFromPath(NULL, kBaseSystemPath);
	if (NULL == aBOM) {
	  	if (gDebugFlag) {
		  error(CFSTR("Initializing SafeBoot bundle error: %s does not exist.\n"), kBaseSystemPath);
		}
		FreeSafeBootContext(aContext);
		return (NULL);
	}

	aBOMPath = BOMBomGetFSObjectAtPath(aBOM, kSystemItemsPath);
	if (NULL == aBOMPath) {
	  	if (gDebugFlag) {
		  error(CFSTR("Initializing SafeBoot bundle error: %s does not exist.\n"), kSystemItemsPath);
		}
		FreeSafeBootContext(aContext);
	  	BOMBomFree(aBOM);
		return (NULL);
	}

	aBOMEnumerator = BOMBomEnumeratorNewWithOptions(aBOM, aBOMPath, BOMBomEnumeratorChildrenOnly | BOMBomEnumeratorPostOrder);
	while ((aEnumStep = BOMBomEnumeratorNext(aBOMEnumerator)) != NULL) {
		CFArrayAppendValue(aContext->aBOMList, BOMFSObjectShortNameString(aEnumStep));
	}

	/*	clean up	*/
	if (aBOMEnumerator) {
		BOMBomEnumeratorFree(aBOMEnumerator);
	}
	BOMFSObjectFree(aBOMPath);
   	BOMBomFree(aBOM);

	/*	if the list is 0 items, no sense keeping the context around	*/
	if (CFArrayGetCount(aContext->aBOMList) < 1) {
		FreeSafeBootContext(aContext);
		return (NULL);
	}

    return(aContext);
}


/*
	clean up the context
*/
void FreeSafeBootContext (SafeBootContext aContext)
{
    if (aContext) {
		if (gDebugFlag) {
			debug(CFSTR("Deallocating SafeBoot bundle context.\n"));
		}
		if (aContext->aBOMList) {
		  	CFRelease(aContext->aBOMList);
		}
		free(aContext);
		aContext = NULL;
	}
}

/*
	See if the string, aBundleName, is in the aBOMList
*/
Boolean CheckSafeBootList(SafeBootContext aContext, char *aBundleName)
{
	if ( (aContext) && (aContext->aBOMList) && (NULL != aBundleName) ) {
		CFIndex i;
		CFIndex myCount = CFArrayGetCount(aContext->aBOMList);
		CFStringRef aTestString;

		for (i=0;i< myCount; i++) {
			aTestString = CFArrayGetValueAtIndex(aContext->aBOMList, i);
			if ( kCFCompareEqualTo == (CFStringCompare(aTestString, CFStringCreateWithCString(NULL, aBundleName, kCFStringEncodingUTF8), 0)) ) {
				return (TRUE);
			}
		}
	}

	return (FALSE);
}
