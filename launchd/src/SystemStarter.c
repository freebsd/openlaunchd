/**
 * SystemStarter.c - System Starter driver
 * Wilfredo Sanchez | wsanchez@opensource.apple.com
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
 **/

#include <unistd.h>
#include <NSSystemDirectories.h>
#include <CoreFoundation/CoreFoundation.h>
#include "main.h"
#include "Log.h"
#include "IPC.h"
#include "StartupItems.h"
#include "StartupDisplay.h"
#include "SystemStarter.h"
#include "SystemStarterIPC.h"

#define kWaitingForKey CFSTR("Waiting for %@")

#define kTimerInterval   3.0	/* Interval of activity checks. */

/**
 * checkForActivity checks to see if any items have completed since the last invokation.
 * If not, a message is displayed showing what item(s) are being waited on.
 **/
static void checkForActivity(CFRunLoopTimerRef aTimer, void* anInfo)
{
    static CFIndex aLastStatusDictionaryCount = -1;
    static CFStringRef aWaitingForString = NULL;
    
    StartupContext aStartupContext = (StartupContext)anInfo;

    if (aStartupContext && aStartupContext->aStatusDict)
      {
        CFIndex aCount = CFDictionaryGetCount(aStartupContext->aStatusDict);

        if (!aWaitingForString)
          {
            aWaitingForString = LocalizedString(aStartupContext->aResourcesBundlePath, kWaitingForKey);
          }
      
        if (aLastStatusDictionaryCount == aCount)
          {
            CFArrayRef aRunningList = StartupItemListGetRunning(aStartupContext->aWaitingList);
            if (aRunningList && CFArrayGetCount(aRunningList) > 0)
              {
                CFMutableDictionaryRef anItem = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(aRunningList, 0);
                CFStringRef anItemDescription = StartupItemGetDescription(anItem);
                CFStringRef aString = aWaitingForString && anItemDescription ? 
                                        CFStringCreateWithFormat(NULL, NULL, aWaitingForString, anItemDescription) : NULL;
                
                if (aString)
                  {
                    displayStatus(aStartupContext->aDisplayContext, aString);
                    CFRelease(aString);
                  }
                if (anItemDescription) CFRelease(anItemDescription);
              }
            if (aRunningList) CFRelease(aRunningList);
          }
        aLastStatusDictionaryCount = aCount;
      }
}

static CFRunLoopTimerRef createActivityTimer(StartupContext aStartupContext)
{
    CFRunLoopTimerContext aTimerContext;
    
    aTimerContext.version = 0;
    aTimerContext.info = aStartupContext;
    aTimerContext.retain = 0;
    aTimerContext.release = 0;
    aTimerContext.copyDescription = 0;

    return CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent(), kTimerInterval, 0, 0, &checkForActivity, &aTimerContext);
}

/*
 * print out any error messages to the log regarding non starting StartupItems
 */
void displayErrorMessages(StartupContext aStartupContext)
{
    if (aStartupContext->aFailedList && CFArrayGetCount(aStartupContext->aFailedList) > 0)
      {
        CFIndex anItemCount = CFArrayGetCount(aStartupContext->aFailedList);
        CFIndex anItemIndex;


        warning(CFSTR("The following StartupItems failed to properly start:\n"));
        
        for (anItemIndex = 0; anItemIndex < anItemCount; anItemIndex++)
          {
            CFMutableDictionaryRef anItem        = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(aStartupContext->aFailedList, anItemIndex);
            CFStringRef anErrorDescription       = CFDictionaryGetValue(anItem, kErrorKey);
            CFStringRef anItemPath               = CFDictionaryGetValue(anItem, kBundlePathKey);
            
            if (anItemPath)
              {
                warning(CFSTR("\t%@"), anItemPath );
              }
            if (anErrorDescription)
              {
                warning(CFSTR(" - %@"), anErrorDescription );
              }
            else
              {
                warning(CFSTR(" - %@"), kErrorInternal );
              }
            warning(CFSTR("\n"));
          }
      }

    if (CFArrayGetCount(aStartupContext->aWaitingList) > 0)
      {
        CFIndex anItemCount = CFArrayGetCount(aStartupContext->aWaitingList);
        CFIndex anItemIndex;
        
        warning(CFSTR("The following StartupItems were not attempted due to failure of a required service:\n"));
        
        for (anItemIndex = 0; anItemIndex < anItemCount; anItemIndex++)
          {
            CFMutableDictionaryRef anItem       = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(aStartupContext->aWaitingList, anItemIndex);
            CFStringRef anItemPath              = CFDictionaryGetValue(anItem, kBundlePathKey);
            if (anItemPath)
              {
                warning(CFSTR("\t%@\n"), anItemPath );
              }
          }
      }
}


int system_starter (Action anAction, CFStringRef aService)
{
    CFRunLoopSourceRef	anIPCSource = NULL;
	NSSearchPathDomainMask	aMask;
    CFRunLoopTimerRef    anActivityTimer = NULL;

    StartupContext   aStartupContext = (StartupContext) malloc(sizeof(struct StartupContextStorage));
    if (! aStartupContext)
      {
        error(CFSTR("Not enough memory to allocate startup context.\n"));
        return(1);
      }

    /**
     * Init the display context.  Starts with the default text display.
     * A graphical display may be requested later via IPC.
     **/
    aStartupContext->aDisplayContext = initDisplayContext();

	aStartupContext->aResourcesBundlePath = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/%@.%s/"),
                                                    kBundleDirectory,
                                                    kResourcesBundleName,
                                                    kBundleExtension);

      {
        CFStringRef aLocalizedString = LocalizedString(aStartupContext->aResourcesBundlePath, kWelcomeToMacintoshKey);
        if (aLocalizedString)
          {
            displayStatus(aStartupContext->aDisplayContext, aLocalizedString);
            CFRelease(aLocalizedString);
          }
      }
      
    if (gSafeBootFlag)
      {
        CFStringRef aLocalizedString = LocalizedString(aStartupContext->aResourcesBundlePath, kSafeBootKey);
        if (aLocalizedString)
          {
            (void) displaySafeBootMsg(aStartupContext->aDisplayContext, aLocalizedString);
            CFRelease(aLocalizedString);
          }
      }

   if (gDebugFlag && gNoRunFlag) sleep(1);

    /**
     * Create the IPC port
     **/
    anIPCSource = CreateIPCRunLoopSource(kSystemStarterMessagePort, aStartupContext);
    if (anIPCSource)
      {
        CFRunLoopAddSource(CFRunLoopGetCurrent(), anIPCSource, kCFRunLoopCommonModes);
        CFRelease(anIPCSource);
      }
    else
      {
        error(CFSTR("Could not create IPC port (%@)."), kSystemStarterMessagePort);
        return(1);
      }

    /**
     * Get a list of Startup Items which are in /Local and /System.
     * We can't search /Network yet because the network isn't up.
     **/
        aMask = NSSystemDomainMask;
        if (!gSafeBootFlag)
          {
            aMask |= NSLocalDomainMask;
          }
        else
          {
            if (gDebugFlag)
              {
                debug(CFSTR("Safe Boot mode active\n")); fflush(stdout);
              }
          }

        aStartupContext->aWaitingList = StartupItemListCreateWithMask(aMask);
        aStartupContext->aFailedList = NULL;
        aStartupContext->aStatusDict  = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                                                                 &kCFTypeDictionaryValueCallBacks);
        aStartupContext->aServicesCount = 0;
        aStartupContext->aRunningCount = 0;
        aStartupContext->aQuitOnNotification = gQuitOnNotification && aStartupContext->aDisplayContext;

        if (aService)
          {
            CFMutableArrayRef aDependentsList = StartupItemListCreateDependentsList(aStartupContext->aWaitingList, aService, anAction);

            if (aDependentsList)
              {
                CFRelease(aStartupContext->aWaitingList);
                aStartupContext->aWaitingList = aDependentsList;
              }
            else 
              {
                error(CFSTR("Unknown service: %@\n"), aService);
                return(1);
              } 
	  }

        aStartupContext->aServicesCount = StartupItemListCountServices(aStartupContext->aWaitingList);

    /**
     * Create the activity timer.
     **/
    anActivityTimer = createActivityTimer(aStartupContext);
        
    /**
     * Do the run loop
     **/
        while (1)
          {
        CFMutableDictionaryRef anItem = StartupItemListGetNext(aStartupContext->aWaitingList, aStartupContext->aStatusDict, anAction);

        if (anItem)
          {
            int err = StartupItemRun(aStartupContext->aStatusDict, anItem, anAction);
            if (!err)
              {
                ++aStartupContext->aRunningCount;
                MonitorStartupItem(aStartupContext, anItem); 
              }
            else
              {
                /* add item to failed list */
                AddItemToFailedList(aStartupContext, anItem);

                /* Remove the item from the waiting list. */
                RemoveItemFromWaitingList(aStartupContext, anItem);
              }
          }
        else
          {
            /* If no item was selected to run, and if no items are running, startup is done. */
            if (aStartupContext->aRunningCount == 0)
              {
                if (gDebugFlag) debug(CFSTR("none left\n"));                      
                break;
              }

            /* Perform periodic checks for activity. */
            if (anActivityTimer)
              {
                CFRunLoopAddTimer(CFRunLoopGetCurrent(), anActivityTimer, kCFRunLoopCommonModes);
              }
            
            /* Process incoming IPC messages and item terminations */
            CFRunLoopRun();
            
            /* Don't perform activity checks while we are doing work. */
            if (anActivityTimer)
              {
                CFRunLoopRemoveTimer(CFRunLoopGetCurrent(), anActivityTimer, kCFRunLoopCommonModes);
              }
          }
      }

    /**
     * Good-bye.
     **/
    displayErrorMessages(aStartupContext);

    /*  Display final message and wait if necessary  */
    {
      CFStringRef aLocalizedString = NULL;
      if (aStartupContext->aQuitOnNotification)
        {
          aLocalizedString = LocalizedString(aStartupContext->aResourcesBundlePath, kLoginWindowKey);
        }
      else
        {
          aLocalizedString = LocalizedString(aStartupContext->aResourcesBundlePath, kStartupCompleteKey);
        }

      if (aLocalizedString)
        {
          displayStatus(aStartupContext->aDisplayContext, aLocalizedString);
          CFRelease(aLocalizedString);
        }
    }

    /* sit and wait for a message from ConsoleMessage to quit */
    if (aStartupContext->aQuitOnNotification)
      {
        CFRunLoopRun();
      }

    /*  clean up  */
    if (anActivityTimer              ) CFRelease(anActivityTimer);
    if (aStartupContext->aStatusDict ) CFRelease(aStartupContext->aStatusDict);
    if (aStartupContext->aWaitingList) CFRelease(aStartupContext->aWaitingList);
    if (aStartupContext->aFailedList)  CFRelease(aStartupContext->aFailedList);
    if (aStartupContext->aResourcesBundlePath) CFRelease(aStartupContext->aResourcesBundlePath);
    
    if (aStartupContext->aDisplayContext) freeDisplayContext(aStartupContext->aDisplayContext);
    free(aStartupContext);
    return(0);
}
