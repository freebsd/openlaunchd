/**
 * StartupDisplay.c - Show Boot Status via the console
 * Wilfredo Sanchez  | wsanchez@opensource.apple.com
 * Kevin Van Vechten | kevinvv@uclink4.berkeley.edu
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
 * Draws status text by printing to the console.
 * This also serves as the default built-in display plug-in, which
 * checks for and loads other plug-ins.
 **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <mach-o/dyld.h>
#include "Log.h"
#include "main.h"

/*
 * This is an opaque (void *) pointer in StarupDisplay.h.
 * The following definition is private to this file.
 */
typedef struct _Text_DisplayContext {
} *DisplayContext;

/*
 * Pointers to functions to call in loaded display plug-in.
 */
static void* (*fInitDisplayContext)(void) = NULL;
static void  (*fFreeDisplayContext)(DisplayContext) = NULL;
static int   (*fDisplayStatus     )(DisplayContext, CFStringRef) = NULL;
static int   (*fDisplayProgress   )(DisplayContext, float      ) = NULL;
static int   (*fDisplaySafeBootMsg)(DisplayContext, CFStringRef) = NULL;

#define _StartupDisplay_C_
#include "StartupDisplay.h"

#define getSymbol(aSymbolName, aPointer) \
{ NSSymbol aSymbol = NSLookupSymbolInModule(aModule, aSymbolName); aPointer = NSAddressOfSymbol(aSymbol); }

/*
 * This function will walk through a list of plugin names to try to load.
 * If it succeeds on any of them, it will set the display function pointers up so that
 * we use them instead of the text drawing code.
 * The first plugin in the list to load is used.
 */
void LoadDisplayPlugIn(CFStringRef aPath)
{
  /* It would be swell if I could just use CFPlugIn */

    NSModule          aModule = NULL;
    NSObjectFileImage anImage;

    CFIndex aPathLength = CFStringGetLength(aPath);
    CFIndex aPathSize   = CFStringGetMaximumSizeForEncoding(aPathLength, kCFStringEncodingUTF8) + 1; /* aPath + null */
    char*   aBundlePath = (char*)malloc(aPathSize);

    CFStringGetCString(aPath, aBundlePath, aPathSize, kCFStringEncodingUTF8);


    if (gDebugFlag) debug(CFSTR("Trying plugin %s..."), aBundlePath);

    if (NSCreateObjectFileImageFromFile(aBundlePath, &anImage) != NSObjectFileImageSuccess ||
            !(aModule = NSLinkModule(anImage, "Display", NSLINKMODULE_OPTION_PRIVATE        |
                                                         NSLINKMODULE_OPTION_RETURN_ON_ERROR)))
      {
        debug(CFSTR("failed\n"));
      }
    else
      {
        getSymbol("__initDisplayContext", fInitDisplayContext);
        getSymbol("__freeDisplayContext", fFreeDisplayContext);
        getSymbol("__displayStatus"     , fDisplayStatus     );
        getSymbol("__displayProgress"   , fDisplayProgress   );
        getSymbol("__displaySafeBootMsg" , fDisplaySafeBootMsg);

        if (fInitDisplayContext &&
            fFreeDisplayContext &&
            fDisplayStatus      &&
            fDisplayProgress    &&
            fDisplaySafeBootMsg )
          {
            if (gDebugFlag) debug(CFSTR("loaded\n"));
          }
        else
          {
            debug(CFSTR("failed to lookup symbols\n"));
            error(CFSTR("Load failure for possibly damaged plugin %s.\n"), aBundlePath);

            if (!NSUnLinkModule(aModule, NSUNLINKMODULE_OPTION_NONE))
              {
                error(CFSTR("Failed to unload symbols for busted plugin.\n"));
              }

            /* Make sure we aren't partly initialized. */
            fInitDisplayContext = NULL;
            fFreeDisplayContext = NULL;
            fDisplayStatus      = NULL;
            fDisplayProgress    = NULL;
            fDisplaySafeBootMsg = NULL;
          }
    }
}

/*
 * Unload the current display bundle.
 */
void UnloadDisplayPlugIn()
{
    fInitDisplayContext = NULL;
    fFreeDisplayContext = NULL;
    fDisplayStatus      = NULL;
    fDisplayProgress    = NULL;
    fDisplaySafeBootMsg = NULL;
}

/*
 * Default drawing routines.
 * Try function pointers if set up, else fall back to text display.
 */

DisplayContext initDisplayContext()
{
  if (fInitDisplayContext) return fInitDisplayContext();

  {
    DisplayContext aContext = (DisplayContext)malloc(sizeof(struct _Text_DisplayContext));

    return(aContext);
  }
}

void freeDisplayContext (DisplayContext aContext)
{
  if (fFreeDisplayContext) return fFreeDisplayContext(aContext);

  if (aContext)
    {
      free(aContext);
    }
}

int displayStatus (DisplayContext aDisplayContext, CFStringRef aMessage)
{
  if (fDisplayStatus) return fDisplayStatus(aDisplayContext, aMessage);

  /**
   * Draw text.
   **/
  if (aMessage)
    {
      message(CFSTR("%@\n"), aMessage);

      return(0);
    }
  return(1);
}

int displayProgress (DisplayContext aDisplayContext, float aPercentage)
{
    if (fDisplayProgress) return fDisplayProgress(aDisplayContext, aPercentage);
    return(0);
}

int displaySafeBootMsg (DisplayContext aDisplayContext, CFStringRef aMessage)
{
  if (fDisplaySafeBootMsg) return fDisplaySafeBootMsg(aDisplayContext, aMessage);

  /**
   * Draw text.
   **/
  if (aMessage)
    {
      message(CFSTR("%@\n"), aMessage);

      return(0);
    }
  return(1);
}

