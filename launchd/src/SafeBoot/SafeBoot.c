/**
 * SafeBoot.c - Additional support for SafeBoot
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
 * Source License Version 1.1 (the "License").  You may not use this file
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
 * Uses private BOM framework if available. Loads the SafeBoot bundle.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include "Log.h"
#include "main.h"


/*
 * This is an opaque (void *) pointer in SafeBoot.h.
 * The following definition is private to this file.
 */
typedef struct _SafeBootContext {
} * SafeBootContext;

/*
 * Pointers to functions to call in loaded SafeBoot plug-in.
 */
static void*   (*fInitSafeBoot)(void) = NULL;
static void    (*fFreeSafeBootContext)(SafeBootContext) = NULL;
static Boolean (*fCheckSafeBootList)(SafeBootContext, char*) = NULL;


#define _SafeBoot_C_
#include "SafeBoot.h"

#define getSymbol(aSymbolName, aPointer) \
{ NSSymbol aSymbol = NSLookupSymbolInModule(aModule, aSymbolName); aPointer = NSAddressOfSymbol(aSymbol); }

/*
 * This function will walk through a list of plugin names to try to load.
 * If it succeeds on any of them, it will set the display function pointers up so that
 * we use them instead of the text drawing code.
 * The first plugin in the list to load is used.
 */
static void autoLoadSafeBootPlugIn()
{
  /* FIXME: This list should be in a plist. */
  char* aPluginList[] = { "SafeBootResources", NULL };
  char* aPlugin;
  int   aPluginIndex;

  for (aPluginIndex = 0; (aPlugin = aPluginList[aPluginIndex]); aPluginIndex++)
    {
      NSModule          aModule = NULL;
      NSObjectFileImage anImage;

      char* aBundlePath = (char*)malloc(strlen(kBundleDirectory) + 1 + /* Path to bundle dir   */
					(strlen(aPlugin)*2)          + /* <name>.bundle/<name> */
					strlen(kBundleExtension) + 2); /* .bundle/ + null      */

      sprintf(aBundlePath, "%s/%s.%s/%s", kBundleDirectory, aPlugin, kBundleExtension, aPlugin);

      if (gDebugFlag) debug(CFSTR("Trying plugin %s..."), aBundlePath);

      if (NSCreateObjectFileImageFromFile(aBundlePath, &anImage) != NSObjectFileImageSuccess ||
	  !(aModule = NSLinkModule(anImage, "SafeBootResources", NSLINKMODULE_OPTION_PRIVATE        |
                                                         NSLINKMODULE_OPTION_RETURN_ON_ERROR)))
	{
		debug(CFSTR("failed\n"));
	}
      else
	{
	  getSymbol("_InitSafeBoot", fInitSafeBoot);
	  getSymbol("_FreeSafeBootContext", fFreeSafeBootContext);
	  getSymbol("_CheckSafeBootList", fCheckSafeBootList);

	  if (fInitSafeBoot &&
	      fFreeSafeBootContext &&
	      fCheckSafeBootList)
	    {
	      if (gDebugFlag) debug(CFSTR("SafeBootResources functions loaded\n"));
	      break;
	    }
	  else
	    {
	      debug(CFSTR("failed to lookup symbols in SafeBootResources\n"));
	      error(CFSTR("Load failure for possibly damaged plugin %s.\n"), aBundlePath);

	      if (!NSUnLinkModule(aModule, NSUNLINKMODULE_OPTION_NONE))
		    {
			  error(CFSTR("Failed to unload symbols for broken plugin.\n"));
			}

	      /* Make sure we aren't partly initialized. */
	      fInitSafeBoot        = NULL;
	      fFreeSafeBootContext = NULL;
	      fCheckSafeBootList   = NULL;
	    }
	}
    }
}

SafeBootContext InitSafeBoot()
{
	autoLoadSafeBootPlugIn();

	if (fInitSafeBoot)
	  {
	  	return fInitSafeBoot();
	  }

	{
		SafeBootContext aContext = (SafeBootContext)malloc(sizeof(struct _SafeBootContext));
		return(aContext);
	}
}

void FreeSafeBootContext (SafeBootContext aContext)
{
  if (fFreeSafeBootContext)
    {
	  return fFreeSafeBootContext(aContext);
	}

  if (aContext)
    {
	  free(aContext);
	  aContext = NULL;
	}
}


Boolean CheckSafeBootList(SafeBootContext aContext, char *aBundleName)
{
  if (fCheckSafeBootList) return fCheckSafeBootList(aContext, aBundleName);

  return TRUE;
}



