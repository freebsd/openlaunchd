/**
 * StartupItems.c - Startup Item management routines
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
 **/

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sysexits.h>
#include <CoreFoundation/CoreFoundation.h>
#include "Log.h"
#include "main.h"
#include "StartupItems.h"
#include "SafeBoot.h"

#define kStartupItemsPath "/StartupItems"
#define kParametersFile   "StartupParameters.plist"
#define kLocalizedDescriptionKey CFSTR("_LocalizedDescription")

#define kRunSuccess CFSTR("success")
#define kRunFailure CFSTR("failure")

typedef enum {
    kPriorityLast    =  1,
    kPriorityLate    =  2,
    kPriorityNone    =  3,
    kPriorityEarly   =  4,
    kPriorityFirst   =  5,
    kPriorityNetwork = 10,
    kPriorityLocal   = 20,
} Priority;

static Priority priorityFromString (CFStringRef aPriority)
{
    if (aPriority)
      {
             if (CFEqual(aPriority, CFSTR("Last" ))) return kPriorityLast  ;
        else if (CFEqual(aPriority, CFSTR("Late" ))) return kPriorityLate  ;
        else if (CFEqual(aPriority, CFSTR("None" ))) return kPriorityNone  ;
        else if (CFEqual(aPriority, CFSTR("Early"))) return kPriorityEarly ;
        else if (CFEqual(aPriority, CFSTR("First"))) return kPriorityFirst ;
      }
    return kPriorityNone;
}

static const char* argumentForAction (Action anAction)
{
    switch (anAction)
      {
      case kActionStart  : return "start"  ;
      case kActionStop   : return "stop"   ;
      case kActionRestart: return "restart";
      default            : return NULL     ;
      }
}

#define checkTypeOfValue(aKey,aTypeID)					\
  {									\
    CFStringRef aProperty = CFDictionaryGetValue(aConfig, aKey);	\
    if (aProperty && CFGetTypeID(aProperty) != aTypeID)			\
      return FALSE;							\
  }

static int StartupItemValidate (CFDictionaryRef aConfig)
{
    if (aConfig && CFGetTypeID(aConfig) == CFDictionaryGetTypeID())
      {
        checkTypeOfValue(kProvidesKey, CFArrayGetTypeID     ());
        checkTypeOfValue(kRequiresKey, CFArrayGetTypeID     ());

        return TRUE;
      }

    return FALSE;
}

/*
 *	remove item from waiting list
 */
void RemoveItemFromWaitingList(StartupContext aStartupContext, CFMutableDictionaryRef anItem)
{
    /* Remove the item from the waiting list. */
    if (aStartupContext && anItem && aStartupContext->aWaitingList)
      {
        CFRange aRange  = {0, CFArrayGetCount(aStartupContext->aWaitingList)};
        CFIndex anIndex = CFArrayGetFirstIndexOfValue(aStartupContext->aWaitingList, aRange, anItem);

        if (anIndex >= 0)
          {
            CFArrayRemoveValueAtIndex(aStartupContext->aWaitingList, anIndex);
          }
      }
}

/*
 *	add item to failed list, create list if it doesn't exist
 *	return and fail quietly if it can't create list
 */
void AddItemToFailedList(StartupContext aStartupContext, CFMutableDictionaryRef anItem)
{
    if (aStartupContext && anItem)
      {
        /* create the failed list if it doesn't exist */
        if (!aStartupContext->aFailedList)
          {
            aStartupContext->aFailedList = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
          }

        if (aStartupContext->aFailedList)
          {
            CFArrayAppendValue(aStartupContext->aFailedList, anItem);
          }
      }
}


/**
 * startupItemListGetMatches returns an array of items which contain the string aService in the key aKey
 **/
static CFMutableArrayRef startupItemListGetMatches (CFArrayRef anItemList, CFStringRef aKey, CFStringRef aService)
{
    CFMutableArrayRef aResult = NULL;

    if (anItemList && aKey && aService)
      {
        CFIndex anItemCount = CFArrayGetCount(anItemList);
        CFIndex anItemIndex = 0;

        aResult = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

        for (anItemIndex = 0; anItemIndex < anItemCount; ++anItemIndex)
          {
            CFMutableDictionaryRef anItem = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(anItemList, anItemIndex);
            CFArrayRef             aList  = CFDictionaryGetValue(anItem, aKey);

            if (aList)
              {
                if (  CFArrayContainsValue(aList,   CFRangeMake(0, CFArrayGetCount(aList)), aService) &&
                    ! CFArrayContainsValue(aResult, CFRangeMake(0, CFArrayGetCount(aResult)), anItem) )
                  {
                    CFArrayAppendValue(aResult, anItem);
                  }
              }
          }
      }
    return aResult;
}

#define kNortonFirewall      CFSTR("Firewall")
#define kNetBarrierFirewall  CFSTR("NetBarrier Firewall")
#define kTimbuktuHost        CFSTR("TimbuktuHost")
#define kNetworkExtensions   CFSTR("NetworkExtensions")
#define kResolver            CFSTR("Resolver")

void SpecialCasesStartupItemHandler(CFMutableDictionaryRef aConfig)
{
    CFMutableArrayRef aProvidesList;

    aProvidesList = (CFMutableArrayRef) CFDictionaryGetValue(aConfig, kProvidesKey);
    if (aProvidesList)
      {
        CFMutableArrayRef aRequiresList;
        CFIndex aProvidesCount = CFArrayGetCount(aProvidesList);

        /* special case for Norton Firewall */
        if (CFArrayContainsValue(aProvidesList, CFRangeMake(0, aProvidesCount), kNetBarrierFirewall))
          {
            aRequiresList = (CFMutableArrayRef) CFDictionaryGetValue(aConfig, kRequiresKey);
            if (!aRequiresList)
              {
                aRequiresList = CFArrayCreateMutable(kCFAllocatorDefault, 1, NULL);
              }

            if (! aRequiresList)
              {
                 return;
              }

            CFArrayAppendValue(aRequiresList, kNetworkExtensions);
            CFDictionaryAddValue(aConfig, kRequiresKey, aRequiresList);
          }

        /* special case for Timbuktu */
        if (CFArrayContainsValue(aProvidesList, CFRangeMake(0, aProvidesCount), kTimbuktuHost))
          {
            aRequiresList = (CFMutableArrayRef) CFDictionaryGetValue(aConfig, kRequiresKey);
            if (! aRequiresList)
              {
                aRequiresList = CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
              }

            if (!aRequiresList)
              {
                return;
              }

            CFArrayAppendValue(aRequiresList, kResolver);
            CFDictionaryAddValue(aConfig, kRequiresKey, aRequiresList);
          }
      }
}

CFIndex StartupItemListCountServices (CFArrayRef anItemList)
{
    CFIndex aResult = NULL;

    if (anItemList)
      {
        CFIndex anItemCount = CFArrayGetCount(anItemList);
        CFIndex anItemIndex = 0;

        for (anItemIndex = 0; anItemIndex < anItemCount; ++anItemIndex)
          {
            CFDictionaryRef     anItem         = CFArrayGetValueAtIndex(anItemList, anItemIndex);
            CFArrayRef          aProvidesList  = CFDictionaryGetValue(anItem, kProvidesKey);

            if (aProvidesList) aResult += CFArrayGetCount(aProvidesList);
          }
      }
    return aResult;
}

CFMutableArrayRef StartupItemListCreateWithMask (NSSearchPathDomainMask aMask)
{
    CFMutableArrayRef anItemList = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

    char aPath[PATH_MAX];
    CFIndex aDomainIndex = 0;
    SafeBootContext    *aSafeBootContext = NULL;

    NSSearchPathEnumerationState aState = NSStartSearchPathEnumeration(NSLibraryDirectory, aMask);

    if (gSafeBootFlag)	
      {
        /*    let's see if the BOM API is available, if so, let's set it up */
        aSafeBootContext = InitSafeBoot();
      }


    while ((aState = NSGetNextSearchPathEnumeration(aState, aPath)))
      {
        DIR* aDirectory;

        strcpy(aPath+strlen(aPath), kStartupItemsPath);
        ++aDomainIndex;

        if ((aDirectory = opendir(aPath)))
          {
            struct dirent* aBundle;

            while ((aBundle = readdir(aDirectory)))
              {
                char *aBundleName = aBundle->d_name;

                char aBundlePath[PATH_MAX];
                char aConfigFile[PATH_MAX];

                if ( aBundleName[0] == '.' ) 
                    continue;

                if (aSafeBootContext)
                  {
                    /*  check to see if item is in the BOM list */
                      if (!CheckSafeBootList(aSafeBootContext, aBundleName))
                        {
                          message(CFSTR("Safe Boot: %s not started.\n"), aBundleName);
                          continue;
                        }
                  }

                if (gDebugFlag) debug(CFSTR("Found item: %s\n"), aBundleName);

                sprintf(aBundlePath, "%s/%s", aPath, aBundleName);
                sprintf(aConfigFile, "%s/" kParametersFile, aBundlePath);

                /* Stow away the plist data for each bundle */
                {
                    int aConfigFileDescriptor;

                    if ((aConfigFileDescriptor = open(aConfigFile, O_RDONLY, (mode_t)0)) != -1)
                      {
                        struct stat aConfigFileStatBuffer;

                        if (stat(aConfigFile, &aConfigFileStatBuffer) != -1)
                          {
                            off_t aConfigFileContentsSize = aConfigFileStatBuffer.st_size;
                            char* aConfigFileContentsBuffer;

                            if ((aConfigFileContentsBuffer =
                                     mmap((caddr_t)0, aConfigFileContentsSize,
                                          PROT_READ, MAP_FILE|MAP_PRIVATE,
                                          aConfigFileDescriptor, (off_t)0)) != (caddr_t)-1)
                              {
                                CFDataRef              aConfigData = NULL;
                                CFMutableDictionaryRef aConfig     = NULL;

                                aConfigData =
                                    CFDataCreateWithBytesNoCopy(NULL,
                                                                aConfigFileContentsBuffer,
                                                                aConfigFileContentsSize,
                                                                kCFAllocatorNull);

                                if (aConfigData)
                                  {
                                    aConfig = (CFMutableDictionaryRef) 
                                              CFPropertyListCreateFromXMLData(NULL, aConfigData,
                                                                kCFPropertyListMutableContainers, NULL);
                                  }

                                if (StartupItemValidate(aConfig))
                                  {
                                    CFStringRef aBundlePathString =
                                        CFStringCreateWithCString(NULL, aBundlePath, kCFStringEncodingUTF8);

                                    CFNumberRef aDomainNumber =
                                        CFNumberCreate(NULL, kCFNumberCFIndexType, &aDomainIndex);

                                    CFDictionarySetValue(aConfig, kBundlePathKey, aBundlePathString);
                                    CFDictionarySetValue(aConfig, kDomainKey, aDomainNumber);
                                    CFRelease(aDomainNumber);
									SpecialCasesStartupItemHandler(aConfig);
                                    CFArrayAppendValue(anItemList, aConfig);

                                    CFRelease(aBundlePathString);
                                  }
                                else
                                  {
                                    error(CFSTR("Malformatted parameters file %s.\n"), aConfigFile);
                                  }

                                if (aConfig    ) CFRelease(aConfig);
                                if (aConfigData) CFRelease(aConfigData);

                                if (munmap(aConfigFileContentsBuffer, aConfigFileContentsSize) == -1)
                                  { warning(CFSTR("Unable to unmap parameters file %s for item %s. (%s)\n"), aConfigFile, aBundleName, strerror(errno)); }
                              }
                            else
                              { error(CFSTR("Unable to map parameters file %s for item %s. (%s)\n"), aConfigFile, aBundleName, strerror(errno)); }
                          }
                        else
                          { error(CFSTR("Unable to stat parameters file %s for item %s. (%s)\n"), aConfigFile, aBundleName, strerror(errno)); }

                        if (close(aConfigFileDescriptor) == -1)
                          { error(CFSTR("Unable to close parameters file %s for item %s. (%s)\n"), aConfigFile, aBundleName, strerror(errno)); }
                      }
                    else
                      { error(CFSTR("Unable to open parameters file %s for item %s. (%s)\n"), aConfigFile, aBundleName, strerror(errno)); }
                }
              }
            if (closedir(aDirectory) == -1)
              { warning(CFSTR("Unable to directory bundle %s. (%s)\n"), aPath, strerror(errno)); }
          }
        else
          {
            if (errno != ENOENT)
              {
                warning(CFSTR("Open on directory %s failed. (%s)\n"), aPath, strerror(errno));
                return(NULL);
              }
          }
      }

    if (aSafeBootContext)
      {
        FreeSafeBootContext(aSafeBootContext);
      }

    return anItemList;
}

CFMutableDictionaryRef StartupItemListGetProvider (CFArrayRef anItemList, CFStringRef aService)
{
    CFMutableDictionaryRef aResult = NULL;
    CFMutableArrayRef      aList   = startupItemListGetMatches(anItemList, kProvidesKey, aService);

    if (aList && CFArrayGetCount(aList) > 0)
      aResult = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(aList, 0);

    return aResult;
}

CFArrayRef StartupItemListGetRunning(CFArrayRef anItemList)
{
    CFMutableArrayRef aResult = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (aResult)
      {
        CFIndex anIndex, aCount = CFArrayGetCount(anItemList);
        for (anIndex = 0; anIndex < aCount; ++anIndex)
          {
            CFDictionaryRef anItem = CFArrayGetValueAtIndex(anItemList, anIndex);
            if (anItem)
              {
                CFNumberRef aPID = CFDictionaryGetValue(anItem, kPIDKey);
                if (aPID) CFArrayAppendValue(aResult, anItem);
              }
          }
      }
    return aResult;
}

/*
 * Append items in anItemList to aDependents which depend on
 *  aParentItem.
 * If anAction is kActionStart, dependent items are those which
 *  require any service provided by aParentItem.
 * If anAction is kActionStop, dependent items are those which provide
 *  any service required by aParentItem.
 */
static void appendDependents (CFMutableArrayRef aDependents,
                              CFArrayRef anItemList, CFDictionaryRef aParentItem,
                              Action anAction)
{
    CFStringRef anInnerKey, anOuterKey;
    CFArrayRef anOuterList;

    /* Append the parent item to the list (avoiding duplicates) */
    if (!CFArrayContainsValue(aDependents, CFRangeMake(0, CFArrayGetCount(aDependents)), aParentItem))
      CFArrayAppendValue(aDependents, aParentItem);

    /**
     * Recursively append any children of the parent item for kStartAction and kStopAction.
     * Do nothing for other actions.
     **/
    switch (anAction)
      {
      case kActionStart: anInnerKey = kProvidesKey; anOuterKey = kRequiresKey; break;
      case kActionStop : anInnerKey = kRequiresKey; anOuterKey = kProvidesKey; break;
      default: return;
      }

    anOuterList = CFDictionaryGetValue(aParentItem, anOuterKey);

    if (anOuterList)
      {
        CFIndex anOuterCount = CFArrayGetCount(anOuterList);
        CFIndex anOuterIndex;
            
        for (anOuterIndex = 0; anOuterIndex < anOuterCount; anOuterIndex++)
          {
            CFStringRef anOuterElement = CFArrayGetValueAtIndex(anOuterList, anOuterIndex);
            CFIndex     anItemCount    = CFArrayGetCount(anItemList);
            CFIndex     anItemIndex;
                
            for (anItemIndex = 0; anItemIndex < anItemCount; anItemIndex++)
              {
                CFDictionaryRef anItem      = CFArrayGetValueAtIndex(anItemList, anItemIndex);
                CFArrayRef      anInnerList = CFDictionaryGetValue(anItem, anInnerKey);

                if (  anInnerList                                                                                     &&
                      CFArrayContainsValue(anInnerList, CFRangeMake(0, CFArrayGetCount(anInnerList)), anOuterElement) &&
                    ! CFArrayContainsValue(aDependents, CFRangeMake(0, CFArrayGetCount(aDependents)), anItem        ) )
                  appendDependents(aDependents, anItemList, anItem, anAction);
              }
          }
      }
}

CFMutableArrayRef StartupItemListCreateDependentsList (CFMutableArrayRef anItemList, CFStringRef aService, Action anAction)
{
    CFMutableArrayRef      aDependents = NULL;
    CFMutableDictionaryRef anItem      = NULL;

    if (anItemList && aService) anItem = StartupItemListGetProvider(anItemList, aService);

    if (anItem)
      {
        switch (anAction)
          {
          case kActionRestart:
          case kActionStart:
          case kActionStop:
            aDependents = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);

            if (!aDependents)
              {
                emergency(CFSTR("Failed to allocate dependancy list for item %@.\n"), anItem);
                return NULL;
              }

            appendDependents(aDependents, anItemList, anItem, anAction);
            break;

          default:
            break;
          }
      }

    return aDependents;
}

/**
 * countUnmetRequirements counts the number of items in anItemList
 * which are pending in aStatusDict.
 **/
static int countUnmetRequirements (CFDictionaryRef aStatusDict, CFArrayRef anItemList)
{
  int     aCount      = 0;
  CFIndex anItemCount = CFArrayGetCount(anItemList);
  CFIndex anItemIndex;

  for (anItemIndex = 0; anItemIndex < anItemCount; anItemIndex++)
    {
      CFStringRef anItem  = CFArrayGetValueAtIndex(anItemList, anItemIndex);
      CFStringRef aStatus = CFDictionaryGetValue(aStatusDict, anItem);

      if (!aStatus || !CFEqual(aStatus, kRunSuccess))
        {
          if (gDebugFlag == 2) debug(CFSTR("\tFailed requirement/uses: %@\n"), anItem);
          aCount++;
        }
    }

    return aCount;
}

/**
 * countDependantsPresent counts the number of items in aWaitingList
 * which depend on items in anItemList.
 **/
static int countDependantsPresent (CFArrayRef aWaitingList, CFArrayRef anItemList, CFStringRef aKey)
{
    int     aCount      = 0;
    CFIndex anItemCount = CFArrayGetCount(anItemList);
    CFIndex anItemIndex;
         
    for (anItemIndex = 0; anItemIndex < anItemCount; anItemIndex++)
      {
        CFStringRef anItem       = CFArrayGetValueAtIndex(anItemList, anItemIndex);
        CFArrayRef  aMatchesList = startupItemListGetMatches(aWaitingList, aKey, anItem);

        if (aMatchesList)
          {
            aCount = aCount + CFArrayGetCount(aMatchesList);
            CFRelease(aMatchesList);
          }
      }

    return aCount;
}

/**
 * pendingAntecedents returns TRUE if any antecedents of this item
 * are currently running, have not yet run, or none exist.
 **/
static Boolean pendingAntecedents (CFArrayRef aWaitingList, CFDictionaryRef aStatusDict, CFArrayRef anAntecedentList, Action anAction)
{
    int aPendingFlag = FALSE;

    CFIndex anAntecedentCount = CFArrayGetCount(anAntecedentList);
    CFIndex anAntecedentIndex;

    for (anAntecedentIndex = 0; anAntecedentIndex < anAntecedentCount; ++anAntecedentIndex)
      {
        CFStringRef anAntecedent = CFArrayGetValueAtIndex(anAntecedentList, anAntecedentIndex);
        CFStringRef aKey         = (anAction == kActionStart) ? kProvidesKey : kUsesKey;
        CFArrayRef  aMatchesList = startupItemListGetMatches(aWaitingList, aKey, anAntecedent);

        if (aMatchesList)
          {
            CFIndex aMatchesListCount = CFArrayGetCount(aMatchesList);
            CFIndex aMatchesListIndex;

            for (aMatchesListIndex = 0; aMatchesListIndex < aMatchesListCount; ++aMatchesListIndex)
              {
                CFDictionaryRef anItem = CFArrayGetValueAtIndex(aMatchesList, aMatchesListIndex);

                if (! anItem                                          ||
                    ! CFDictionaryGetValue(anItem,      kPIDKey     ) ||
                    ! CFDictionaryGetValue(aStatusDict, anAntecedent) )
                  {
                    aPendingFlag = TRUE;
                    break;
                  }
              }

            CFRelease(aMatchesList);

            if (aPendingFlag) break;
          }
      }
    return (aPendingFlag);
}

/**
 * checkForDuplicates returns TRUE if an item provides the same service as a
 * pending item, or an item that already succeeded.
 **/
static Boolean checkForDuplicates (CFArrayRef aWaitingList, CFDictionaryRef aStatusDict, CFDictionaryRef anItem)
{
    int aDuplicateFlag = FALSE;

    CFArrayRef  aProvidesList  = CFDictionaryGetValue(anItem, kProvidesKey);
    CFIndex     aProvidesCount = aProvidesList ? CFArrayGetCount(aProvidesList) : 0;
    CFIndex     aProvidesIndex;

    for (aProvidesIndex = 0; aProvidesIndex < aProvidesCount; ++aProvidesIndex)
      {
        CFStringRef aProvides    = CFArrayGetValueAtIndex(aProvidesList, aProvidesIndex);

        /* If the service succeeded, return true. */
        CFStringRef aStatus = CFDictionaryGetValue(aStatusDict, aProvides);
        if (aStatus && CFEqual(aStatus, kRunSuccess))
          {
            aDuplicateFlag = TRUE;
            break;
          }
        /* Otherwise test if any item is currently running which might provide that service. */
        else
          { 
            CFArrayRef aMatchesList = startupItemListGetMatches(aWaitingList, kProvidesKey, aProvides);
            if (aMatchesList)
              {
                CFIndex aMatchesListCount = CFArrayGetCount(aMatchesList);
                CFIndex aMatchesListIndex;

                for (aMatchesListIndex = 0; aMatchesListIndex < aMatchesListCount; ++aMatchesListIndex)
                  {
                    CFDictionaryRef anDupItem = CFArrayGetValueAtIndex(aMatchesList, aMatchesListIndex);
                    if (anDupItem && CFDictionaryGetValue(anDupItem, kPIDKey))
                      {
                        /* Item is running, avoid race condition. */
                        aDuplicateFlag = TRUE;
                        break;
                      }
                    else
                      {
                        CFNumberRef anItemDomain = CFDictionaryGetValue(anItem, kDomainKey);
                        CFNumberRef anotherItemDomain = CFDictionaryGetValue(anDupItem, kDomainKey);
                        /* If anItem was found later than aDupItem, stall anItem until aDupItem runs. */
                        if (anItemDomain &&
                            anotherItemDomain &&
                            CFNumberCompare(anItemDomain, anotherItemDomain, NULL) == kCFCompareGreaterThan)
                          {
                            /* Item not running, but takes precedence. */
                            aDuplicateFlag = TRUE;
                            break;
                          }
                      }
                  }

                CFRelease(aMatchesList);
                if (aDuplicateFlag) break;
              }
          }
      }
    return (aDuplicateFlag);
}

CFMutableDictionaryRef StartupItemListGetNext (CFArrayRef aWaitingList, CFDictionaryRef aStatusDict, Action anAction)
{
    CFMutableDictionaryRef aNextItem     = NULL;
    CFIndex                aWaitingCount = CFArrayGetCount(aWaitingList);

    switch (anAction)
      {
      case kActionStart  : break;
      case kActionStop   : break;
      case kActionRestart: break;
      default: return NULL;
      }

    if (aWaitingList && aStatusDict && aWaitingCount > 0)
      {
        Priority aMaxPriority          = kPriorityLast;
        int      aMinFailedAntecedents = INT_MAX;
        CFIndex  aWaitingIndex;

        /**
         * Iterate through the items in aWaitingList and look for an optimally ready item.
         **/
        for (aWaitingIndex = 0; aWaitingIndex < aWaitingCount; aWaitingIndex++)
          {
            CFMutableDictionaryRef anItem = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(aWaitingList, aWaitingIndex);
            CFArrayRef anAntecedentList;

            /* Filter out running items. */
            if (CFDictionaryGetValue(anItem, kPIDKey)) goto next_item;

            /* Filter out dupilicate services; if someone has provided what we provide, we don't run. */
            if (checkForDuplicates(aWaitingList, aStatusDict, anItem))
            {
                if (gDebugFlag == 2) debug(CFSTR("Skipping %@ because of duplicate service.\n"), CFDictionaryGetValue(anItem, kDescriptionKey));
                goto next_item;
            }
            
            /* Dependencies don't matter when restarting an item; stop here. */
            if (anAction == kActionRestart)
              {
                aNextItem = anItem;
                break;
              }

            anAntecedentList = CFDictionaryGetValue(anItem, ((anAction == kActionStart) ? kRequiresKey : kProvidesKey));

            if (gDebugFlag == 2)
              {
                debug(CFSTR("Checking %@.\n"), CFDictionaryGetValue(anItem, kDescriptionKey));

                if (anAntecedentList)
                  debug(CFSTR("\tAntecedents: %@\n"), anAntecedentList);
                else
                  debug(CFSTR("\tNo antecedents.\n"));
              }

            /**
             * Filter out the items which have unsatisfied antecedents.
             **/
            if (anAntecedentList &&
                ((anAction == kActionStart) ?
                 countUnmetRequirements(aStatusDict, anAntecedentList) :
                 countDependantsPresent(aWaitingList, anAntecedentList, kRequiresKey)))
              goto next_item;

            /**
             * anItem has all hard dependancies met; check for soft dependancies.
             * We'll favor the item with the fewest unmet soft dependancies here.
             **/
            {
              int     aFailedAntecedentsCount = 0;     /* Number of unmet soft depenancies */
              Boolean aBestPick               = FALSE; /* Is this the best pick so far?    */

              anAntecedentList = CFDictionaryGetValue(anItem, ((anAction == kActionStart) ?
                                                               kUsesKey : kProvidesKey));

              if (gDebugFlag == 2)
                {
                  if (anAntecedentList)
                    debug(CFSTR("\tSoft dependancies: %@\n"), anAntecedentList);
                  else
                    debug(CFSTR("\tNo soft dependancies.\n"));
                }

              if (anAntecedentList)
                {
                  aFailedAntecedentsCount =
                    ((anAction == kActionStart) ?
                     countUnmetRequirements(aStatusDict, anAntecedentList) :
                     countDependantsPresent(aWaitingList, anAntecedentList, kUsesKey));
                }
              else
                {
                  if (aMinFailedAntecedents > 0) aBestPick = TRUE;
                }

              /* anItem has unmet dependencies that will likely be met in the future, so delay it*/
              if (aFailedAntecedentsCount > 0 &&
                  pendingAntecedents(aWaitingList, aStatusDict, anAntecedentList, anAction))
                {
                  goto next_item;
                }

              if (gDebugFlag == 2 && aFailedAntecedentsCount > 0) debug(CFSTR("\tTotal: %d\n"), aFailedAntecedentsCount);

              if (aFailedAntecedentsCount > aMinFailedAntecedents) goto next_item; /* Another item already won out */
              if (aFailedAntecedentsCount < aMinFailedAntecedents) aBestPick = TRUE;

              {
                Priority aPriority = priorityFromString(CFDictionaryGetValue(anItem, kPriorityKey));

                if (aBestPick)
                  {
                    /* anItem has less unmet dependancies than any other item so far, so it wins. */
                    if (gDebugFlag == 2)
                      debug(CFSTR("\tBest pick so far, based on failed dependancies (%d->%d).\n"),
                            aMinFailedAntecedents, aFailedAntecedentsCount);
                  }
                else if ((anAction == kActionStart) ?
                         (aPriority >= aMaxPriority) :
                         (aPriority <= aMaxPriority))
                  {
                    /* anItem has a best priority, so it wins. */
                    if (gDebugFlag == 2)
                      debug(CFSTR("\tBest pick so far, based on Priority (%d->%d).\n"),
                            aMaxPriority, aPriority);
                  }
                else
                  goto next_item; /* No soup for you! */

                /* We have a winner!  Update success parameters to match anItem. */
                aMinFailedAntecedents = aFailedAntecedentsCount;
                aMaxPriority          = aPriority;
                aNextItem             = anItem;
              }

            } /* End of uses section. */

          next_item:
            continue;

          } /* End of waiting list loop. */

      } /* if (aWaitingList && aWaitingCount > 0) */

    return aNextItem;
}

CFStringRef StartupItemGetDescription(CFMutableDictionaryRef anItem)
{
    if (anItem)
      {
        CFStringRef aString = CFDictionaryGetValue(anItem, kLocalizedDescriptionKey);
        if (aString)
          {
            return CFRetain(aString);
          }
        else
          {
            CFStringRef aString = CFDictionaryGetValue(anItem, kDescriptionKey);
            if (aString)
              {
                CFStringRef aLocalizedString = StartupItemCreateLocalizedString(anItem, aString);
                if (aLocalizedString)
                  {
                    CFDictionarySetValue(anItem, kLocalizedDescriptionKey, aLocalizedString);
                    return aLocalizedString;
                  }
                else
                  {
                    return CFRetain(aString);
                  }
              }
          }
      }
    return NULL;
}

pid_t StartupItemGetPID(CFDictionaryRef anItem)
{
    CFIndex                anItemPID = 0;
    CFNumberRef            aPIDNumber = anItem ? CFDictionaryGetValue(anItem, kPIDKey) : NULL;
    if (aPIDNumber && CFNumberGetValue(aPIDNumber, kCFNumberCFIndexType, &anItemPID))
        return (pid_t)anItemPID;
    else
        return 0;
}

CFMutableDictionaryRef StartupItemWithPID (CFArrayRef anItemList, pid_t aPID)
{
  CFIndex anItemCount = CFArrayGetCount(anItemList);
  CFIndex anItemIndex;

  for (anItemIndex = 0; anItemIndex < anItemCount; anItemIndex++)
    {
      CFMutableDictionaryRef anItem     = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(anItemList, anItemIndex);
      CFNumberRef            aPIDNumber = CFDictionaryGetValue(anItem, kPIDKey);
      CFIndex                anItemPID;

      if (aPIDNumber)
        {
          CFNumberGetValue(aPIDNumber, kCFNumberCFIndexType, &anItemPID);

          if ((pid_t)anItemPID == aPID) return anItem;
        }
    }

    return NULL;
}

int StartupItemRun (CFMutableDictionaryRef aStatusDict, CFMutableDictionaryRef anItem, Action anAction)
{
  	int anError = -1;

    if (anAction == kActionNone)
      {
        StartupItemExit(aStatusDict, anItem, TRUE);
        anError = 0;
      }
    else
      {
        CFStringRef aBundlePathString = CFDictionaryGetValue(anItem, kBundlePathKey);
        size_t aBundlePathCLength =
            CFStringGetMaximumSizeForEncoding(CFStringGetLength(aBundlePathString), kCFStringEncodingUTF8) + 1;
        char *aBundlePath = (char*)malloc(aBundlePathCLength);
        char anExecutable[PATH_MAX] = "";

        if (! aBundlePath)
          {
            emergency(CFSTR("malloc() failed; out of memory while running item %s"), aBundlePathString);
            return (anError);
          }

        if (! CFStringGetCString(aBundlePathString, aBundlePath, aBundlePathCLength, kCFStringEncodingUTF8))
          {
            emergency(CFSTR("Internal error while running item %@"), aBundlePathString);
            return (anError);
          }

        /* Compute path to excecutable */
        {
          char *tmp;
          strcpy(anExecutable, aBundlePath);              /* .../foo     */
          tmp = rindex(anExecutable, '/');                /* /foo        */
          strncat(anExecutable, tmp, strlen(tmp));        /* .../foo/foo */
        }

        free(aBundlePath);

        /**
         * Run the bundle
         **/

        if (access(anExecutable, X_OK))
          {
            /* Add PID key so that this item is marked as having been run. */
            CFIndex     aPID           = -1;
            CFNumberRef aProcessNumber = CFNumberCreate(NULL, kCFNumberCFIndexType, &aPID);

            CFDictionarySetValue(anItem, kPIDKey, aProcessNumber);
            CFRelease(aProcessNumber);

            CFDictionarySetValue(anItem, kErrorKey, kErrorPermissions);
            StartupItemExit(aStatusDict, anItem, FALSE);
            error(CFSTR("No executable file %s\n"), anExecutable);
          }
        else
          {
            pid_t aProccessID = fork();

            switch (aProccessID)
              {
              case -1: /* SystemStarter (fork failed) */
                CFDictionarySetValue(anItem, kErrorKey, kErrorFork);
                StartupItemExit(aStatusDict, anItem, FALSE);

                error(CFSTR("Failed to fork for item %@: %s\n"),
                      aBundlePathString, strerror(errno));

                break;

              default: /* SystemStarter (fork succeeded) */
                {
                  CFIndex     aPID           = (CFIndex)aProccessID;
                  CFNumberRef aProcessNumber = CFNumberCreate(NULL, kCFNumberCFIndexType, &aPID);

                  CFDictionarySetValue(anItem, kPIDKey, aProcessNumber);
                  CFRelease(aProcessNumber);

                  if (gDebugFlag)
                    message(CFSTR("Running command (%d): %s %s\n"),
                            aProccessID, anExecutable, argumentForAction(anAction));
                  anError = 0;
                }
                break;

              case 0: /* Child */
                if (gNoRunFlag)
                  {
                    if (gDebugFlag) sleep(1 + (random() % 3));

                    exit(0);
                  }
                else
                  {
                    char *const aNullEnvironment[] = { NULL };

                    if (setsid() == -1)
                      warning(CFSTR("Unable to create session for item %@: %s\n"),
                              aBundlePathString, strerror(errno));

                    /* Close open file descriptors. */
                    {
                      int anFD;
                      for (anFD = getdtablesize() - 1; anFD > STDERR_FILENO; anFD--) close(anFD);
                    }

                    anError = execle(anExecutable,
                                        anExecutable, argumentForAction(anAction), NULL,
                                        aNullEnvironment);

                    /* We shouldn't get here. */

                    error(CFSTR("Exec failed for item %@: %s\n"),
                          aBundlePathString, strerror(errno));

                    exit(anError);
                  }
              }
          }
      }

    return (anError);
}

void StartupItemSetStatus(CFMutableDictionaryRef aStatusDict, CFMutableDictionaryRef anItem, CFStringRef aServiceName, Boolean aSuccess, Boolean aReplaceFlag)
{
    void (*anAction)(CFMutableDictionaryRef, const void *, const void *) = aReplaceFlag ?
                        CFDictionarySetValue : CFDictionaryAddValue;
        
    if (aStatusDict && anItem)
      {
        CFArrayRef aProvidesList = CFDictionaryGetValue(anItem, kProvidesKey);
        if (aProvidesList)
          {
            CFIndex aProvidesCount = CFArrayGetCount(aProvidesList);
            CFIndex aProvidesIndex;
            
            /* If a service name was specified, and it is valid, use only it. */
            if (aServiceName && CFArrayContainsValue(aProvidesList, CFRangeMake(0, aProvidesCount), aServiceName))
              {
                aProvidesList  = CFArrayCreate(NULL, (const void**) &aServiceName, 1, &kCFTypeArrayCallBacks);
                aProvidesCount = 1;
              }
            else
              {
                CFRetain(aProvidesList);
              }

            for (aProvidesIndex = 0; aProvidesIndex < aProvidesCount; aProvidesIndex++)
              {
                CFStringRef aService = CFArrayGetValueAtIndex(aProvidesList, aProvidesIndex);

                if (aSuccess)
                    anAction(aStatusDict, aService, kRunSuccess);
                else
                    anAction(aStatusDict, aService, kRunFailure);
              }
            
            CFRelease(aProvidesList);
          }
      }
}

void StartupItemExit (CFMutableDictionaryRef aStatusDict, CFMutableDictionaryRef anItem, Boolean aSuccess)
{
    StartupItemSetStatus(aStatusDict, anItem, NULL, aSuccess, FALSE);
    
    if (gParentPID && anItem)
      {
        CFArrayRef aProvidesList = CFDictionaryGetValue(anItem, kProvidesKey);
        if (aProvidesList)
          {
            CFIndex aProvidesCount = CFArrayGetCount(aProvidesList);
            if (CFArrayContainsValue(aProvidesList, CFRangeMake(0, aProvidesCount), kLoginService))
              {
                kill(gParentPID, SIGHUP);
                gParentPID = 0;
              }
           }
        }
}

CFStringRef StartupItemCreateLocalizedString (CFDictionaryRef anItem, CFStringRef aString)
{
    CFStringRef aBundlePath = NULL;

    aBundlePath = CFDictionaryGetValue(anItem, kBundlePathKey);

    return ( StartupItemCreateLocalizedStringWithPath (aBundlePath, aString));
}

 

CFStringRef StartupItemCreateLocalizedStringWithPath (CFStringRef aBundlePath, CFStringRef aString)
{
    char *aLanguage = getenv("LANGUAGE");
    CFStringRef aRealResult = NULL;
    CFURLRef aBundleURL = NULL;
    CFBundleRef aBundleRef = NULL;
    CFURLRef aLocURL = NULL;
    CFStringRef aLangRef = NULL;
    CFDataRef aLocData = NULL;
    CFMutableDictionaryRef aStringsDict = NULL;

    aLangRef = CFStringCreateWithCString(kCFAllocatorDefault,
                        ( aLanguage ? aLanguage : ""),
                        kCFStringEncodingASCII); /* CFRelease() */

    aBundleURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, aBundlePath,
                        kCFURLPOSIXPathStyle, true );        /* CFRelease() */

    if(!aBundleURL)
      {
        error(CFSTR("Unable to get URL for bundle at %@\n"), aBundlePath);
        CFRelease(aLangRef);
        return CFRetain(aString);
      }

    aBundleRef = CFBundleCreate(kCFAllocatorDefault, aBundleURL); /* CFRelease() */
    if(!aBundleRef)
      {
        error(CFSTR("Unable to load bundle at %@\n"), aBundlePath);
        CFRelease(aBundleURL);
        CFRelease(aLangRef);
        return CFRetain(aString);
      }

    CFRelease(aBundleURL); /* Still alloced: aLangRef, aBundleRef */

    aLocURL = CFBundleCopyResourceURLForLocalization(aBundleRef,
                        CFSTR("Localizable"),
                        CFSTR("strings"),
                        NULL,
                        aLangRef); /* CFRelease() */
    
    CFRelease(aLangRef); /* Still alloced: aLocURL, aBundleRef */

    if(!aLocURL)
      {
        aLocURL = CFBundleCopyResourceURL(aBundleRef,
                        CFSTR("Localizable"),
                        CFSTR("strings"),
                        NULL);
        if(!aLocURL)
          {
            /* no localizable strings anywhere */
            if (gDebugFlag) debug(CFSTR("Unable to load localization strings for %@\n"), aBundlePath);
            CFRelease(aBundleRef);
            return CFRetain(aString);
          }
      }

    CFRelease(aBundleRef); /* Still alloced: aLocURL */
    /* We have a localization file */

    if(!CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, aLocURL,
                        &aLocData, NULL, NULL, NULL))                /* CFRelease() */
      {
        warning(CFSTR("Bad localization strings file at %@\n"), aLocURL);
        CFRelease(aLocURL);
        return CFRetain(aString);
      }

    aStringsDict =  (CFMutableDictionaryRef)
    CFPropertyListCreateFromXMLData(NULL,
                        aLocData,
                        kCFPropertyListMutableContainers,
                        NULL);  /* CFRelease() */

    CFRelease(aLocData);  /* Still alloced: aLocURL, aStringsDict */

    if (!aStringsDict || CFGetTypeID(aStringsDict) != CFDictionaryGetTypeID())
      {
        error(CFSTR("Malformatted strings file %@.\n"), aLocURL);
        CFRelease(aLocURL);
        if(aStringsDict) CFRelease(aStringsDict);
        return CFRetain(aString);
      }

    aRealResult = CFDictionaryGetValue(aStringsDict, aString);

    CFRelease(aLocURL); /* Still alloced: aStringsDict */

    if(aRealResult)
      {
        CFRetain(aRealResult);
      }

    CFRelease(aStringsDict);

    if(!aRealResult)
      {
        return CFRetain(aString);
      }
    else
      {
        return aRealResult;
      }

    return CFRetain(aString); /* shouldn't get here */
 }

