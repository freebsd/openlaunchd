/**
 * QuartzDisplay.c - Show Boot Status via CoreGraphics
 * Wilfredo Sanchez | wsanchez@opensource.apple.com
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
 * Draws the startup screen, progress bar and status text using
 * CoreGraphics (Quartz).
 *
 * WARNING: This code uses private Core Graphics API.  Private API is
 * subject to change at any time without notice, and it's use by
 * parties unknown to the Core Graphics authors is in no way supported.
 * If you borrow code from here for other use and it later breaks, you
 * have no basis for complaint.
 **/

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreGraphics/CGPDFDocument.h>
#include <CoreGraphics/CoreGraphicsPrivate.h>
#include <CoreGraphics/CGFontEncoding.h>
#include <CoreFoundation/CFPriv.h>
#include "../Log.h"
#include "../main.h"
#include "QuartzProgressBar.h"

/*
 * This is an opaque (void *) pointer in StarupDisplay.h.
 * The following definition is private to this file.
 */
typedef struct _CGS_DisplayContext {
    CGSConnectionID connectionID;
    CGSWindowID	    bootImageWindowID;
    CGContextRef    bootImageContext;
    CGRect          bootImageRect;
    CGSWindowID	    statusWindowID;
    CGSWindowID	    safeBootWindowID;
    CGContextRef    statusContext;
    CGContextRef    safeBootContext;
    CGContextRef    progressContext;
    ProgressBarRef  progressBar;
} *DisplayContext;
#define _StartupDisplay_C_
#include "../StartupDisplay.h"

/* FIXME: Move all of this into a plist. */
/* Bounds for Boot Panel text specified by UE team, 2/7/2002 */
#define kTransparentColor	0.0,0.0,0.0,0.0
#define kAutoFillColor		0.4,0.4,0.6
#define kStatusAreaColor	kTransparentColor
#define kStatusAreaHeight	 62.0
#define kStatusAreaWidth	350.0
#define kStatusAreaXOffset	 -3.0
#define kStatusTextFont		"LucidaGrande"
#define kStatusTextColor	0.0,0.0,0.0,1.0
#define kStatusTextFontSize	 13.0
#define kStatusBarWidth		220.0
#define kStatusBarHeight	 21.0
#define kStatusBarPosX		((kStatusAreaWidth-kStatusBarWidth)/2.0)
#define kStatusBarPosY		(kStatusAreaHeight-kStatusBarHeight)

#define kSafeBootAreaHeight	 38.0
#define kSafeBootAreaWidth	300.0
#define kSafeBootTextFont	"LucidaGrande-Bold"
#define kSafeBootTextColor	0.0,0.0,0.0,1.0
#define kSafeBootTextFontSize    12.0
#define kSafeBootXOffset         31.0


static CGSConnectionID _initDisplayConnection()
{
    CGSConnectionID aConnectionID;
    CGError aErr;

    /*
       Using CGSServerPort() now to see if Window Server is running. CGSServerPort blocks for up
       to 10 seconds until Window Server is running or until timeout.
     */
    CGSMachPort aCGSMachPort = CGSServerPort();
    if (aCGSMachPort == kCGSMachPortNull)
      {
	debug(CFSTR("_initDisplayConnection:  aCGSMachPort == NULL \n"));
        return(NULL);
      }

    /* Initialize Core Graphics */
    if ((aErr = CGSInitialize()) != kCGErrorSuccess)
      {
        error(CFSTR("Core Graphics could not initialize. Failed with error %ld.\n"), aErr);
        return(NULL);
      }

    /* Connect to Window Server */
    if ((CGSNewConnection(NULL, &aConnectionID)) != kCGSErrorSuccess)
      {
        return(NULL);
      }

    return(aConnectionID);
}

static int _closeDisplayConnection(CGSConnectionID aConnectionID)
{
    if ((CGSReleaseConnection(aConnectionID)) != kCGSErrorSuccess)
	return(1);

    return(0);
}

static int _initWindowContext(CGSConnectionID aConnectionID,
                  CGSWindowID*    aWindowID,
                  CGContextRef*   aContext,
                  CGRect          aRectangle,
                  CGSBoolean      aShadowOption,
                  CGSBoolean      aTransparentOption)
{
    /**
     * Create a window at (aPosX,aPosY) with size (aWidth,aHeight).
     **/
    {
    CGSRegionObj aRegion;

    CGSNewRegionWithRect(&aRectangle, &aRegion);

    if (CGSNewWindow(aConnectionID, kCGSBufferedBackingType, 0.0, 0.0, aRegion, aWindowID) != kCGSErrorSuccess)
     { warning(CFSTR("CGSNewWindow failed.\n")); return(1); }

    if (aRegion)
      {
        (void) CGSReleaseRegion(aRegion); 
      }

    /* Enable/disable the drop-shadow on this window */
    {
        CGSValueObj	 aKey, aShadow;

        aKey    = CGSCreateCString("HasShadow");
        aShadow = CGSCreateBoolean(aShadowOption);

        CGSSetWindowProperty(aConnectionID, *aWindowID, aKey, aShadow);

        CGSReleaseGenericObj(aKey);
        CGSReleaseGenericObj(aShadow);
    }

    /* Set background color for window. */
    CGSSetWindowAutofillColor(aConnectionID, *aWindowID, kAutoFillColor);
    }

    /* set up window context */
    *aContext = CGWindowContextCreate(aConnectionID, *aWindowID, NULL);
    if (*aContext == NULL)
      {
        warning(CFSTR("CGWindowContextCreate failed.\n"));
        return(1);
      }
    CGContextErase(*aContext);
    
    /* Make the window transparent if requested. */
    if (aTransparentOption == kCGSTrue)
      {
        CGRect aLocalRect = CGRectMake(0.0, 0.0, CGRectGetWidth(aRectangle), CGRectGetHeight(aRectangle));

        /* Enable transparency for this window. */
        CGSSetWindowOpacity(aConnectionID, *aWindowID, kCGSFalse);

        CGContextSaveGState           (*aContext);
        CGContextSetCompositeOperation(*aContext, kCGCompositeCopy);
        CGContextSetRGBFillColor      (*aContext, kTransparentColor);
        CGContextFillRect             (*aContext, aLocalRect);
	CGContextRestoreGState        (*aContext);
        CGContextFlush                (*aContext);
      }

    return (0);
}

static int _initBootImageContext (DisplayContext aDisplayContext)
{
    CGSConnectionID aConnectionID = aDisplayContext->connectionID;
    CGSWindowID*    aWindowID	  = &aDisplayContext->bootImageWindowID;
    CGContextRef*   aContext	  = &aDisplayContext->bootImageContext;
    CFStringRef	    aString;
    
    
    /*	Determine if we're running Server or Desktop config	*/
    /*	This is the standard way to determine Server/Desktop	*/
    CFDictionaryRef	serverDict;
    Boolean	isServerConfig = false;
    
    if ((serverDict = _CFCopyServerVersionDictionary()) != NULL) {
        CFRelease(serverDict);
        isServerConfig = true;
    }

    if (isServerConfig) {
        aString = CFSTR(kServerBootImagePath);
    } else {
        aString = CFSTR(kBootImagePath);
    }

    if (aConnectionID)
      {
	CGPDFDocumentRef anImageDoc;
	CFURLRef	aURL;

	srandom ((time(NULL) & 0xffff) | ((getpid() & 0xffff) << 16));

	aURL = CFURLCreateWithFileSystemPath(NULL, aString,
						kCFURLPOSIXPathStyle, FALSE);
	anImageDoc = CGPDFDocumentCreateWithURL(aURL);
	CFRelease(aURL);
	if (anImageDoc)
	  {
	    CGRect	 aDisplayRect;
	    CGRect	 anImageRectCG;
	    CGRect	 anImageRect;
	    CGSRegionObj anImageRegion;

	    int aPageCount = CGPDFDocumentGetNumberOfPages(anImageDoc);
	    int aPage = (int)(random() % aPageCount) + 1;

	    if (! (aPageCount > 0))
	      {
		error(CFSTR("Boot image has no pages.\n"));
		return(1);
	      }

	    CGSGetDisplayBounds((CGSDisplayNumber)0, &aDisplayRect); /* Bounds for display 0 */

	    anImageRectCG = CGPDFDocumentGetMediaBox(anImageDoc, aPage);

	    /* Crap. We need to convert the CGRect into a CGSRect. */
	    anImageRect.origin.x    = aDisplayRect.origin.x + ((aDisplayRect.size.width	 - anImageRectCG.size.width )/2.0);
	    anImageRect.origin.y    = aDisplayRect.origin.y + ((aDisplayRect.size.height - anImageRectCG.size.height)/2.0);
	    anImageRect.size.width  = anImageRectCG.size.width;
	    anImageRect.size.height = anImageRectCG.size.height;

	    CGSNewRegionWithRect(&anImageRect, &anImageRegion);
	    CGSGetRegionBounds(anImageRegion, &anImageRect);
            if (anImageRegion)
	      {
                (void) CGSReleaseRegion(anImageRegion);
              }
	    aDisplayContext->bootImageRect = anImageRect;

	    if (_initWindowContext(aConnectionID, aWindowID, aContext, anImageRect, kCGSTrue, kCGSFalse))
	      {
			error(CFSTR("Can't create window context.\n"));
			return(1);
	      }

	    CGContextDrawPDFDocument(*aContext, anImageRectCG, anImageDoc, aPage);
	    CGPDFDocumentRelease(anImageDoc);

	    CGContextFlush 	(*aContext);

	    if (CGSOrderWindow(aConnectionID, *aWindowID, kCGSOrderAbove, (CGSWindowID)0) != kCGSErrorSuccess)
	      { warning(CFSTR("CGSOrderWindow failed")); }

	    return(0);
	  }
	else
	    warning(CFSTR("Can't find boot image %s."), kBootImagePath);
      }

    return(1);
}

static int _initStatusWindowContext (DisplayContext aDisplayContext)
{
    CGSConnectionID aConnectionID =  aDisplayContext->connectionID;
    CGSWindowID*    aWindowID	  = &aDisplayContext->statusWindowID;
    CGContextRef*   aContext	  = &aDisplayContext->statusContext;

    if (aConnectionID)
      {
	CGRect aDisplayRect;
	CGRect aTextFieldRect;

	CGSGetDisplayBounds(0, &aDisplayRect);	/* Bounds for Display 0 */

	aTextFieldRect =
	    CGRectMake(aDisplayRect.origin.x + ((aDisplayRect.size.width -kStatusAreaWidth )/2.0),
			aDisplayRect.origin.y + ((aDisplayRect.size.height-kStatusAreaHeight)/2.0) + (aDisplayContext->bootImageRect.size.height/4.0) + kStatusAreaXOffset,
			kStatusAreaWidth, kStatusAreaHeight);

	if (_initWindowContext(aConnectionID, aWindowID, aContext, aTextFieldRect, kCGSFalse, kCGSTrue))
	  {
	    error(CFSTR("Can't create window context.\n"));
	    return(1);
	  }
      }

    return(0);
}

static int _initSafeBootWindowContext (DisplayContext aDisplayContext)
{
    CGSConnectionID aConnectionID =  aDisplayContext->connectionID;
    CGSWindowID*    aWindowID	  = &aDisplayContext->safeBootWindowID;
    CGContextRef*   aContext	  = &aDisplayContext->safeBootContext;

    if (aConnectionID)
      {
	CGRect aDisplayRect;
	CGRect aTextFieldRect;

	CGSGetDisplayBounds(0, &aDisplayRect);	/* Bounds for Display 0 */

	aTextFieldRect =
	    CGRectMake(aDisplayRect.origin.x + ((aDisplayRect.size.width -kSafeBootAreaWidth )/2.0),
			aDisplayRect.origin.y + ((aDisplayRect.size.height-kSafeBootAreaHeight)/2.0) + (aDisplayContext->bootImageRect.size.height/4.0) + kSafeBootXOffset,
			kSafeBootAreaWidth, kSafeBootAreaHeight);

	if (_initWindowContext(aConnectionID, aWindowID, aContext, aTextFieldRect, kCGSFalse, kCGSTrue))
	  {
	    error(CFSTR("Can't create window context."));
	    return(1);
	  }
      }

    return(0);
}

DisplayContext _initDisplayContext()
{
    DisplayContext aContext = (DisplayContext)malloc(sizeof(struct _CGS_DisplayContext));

    if (NULL == aContext)
      {
      	if (gDebugFlag)
          {
            error(CFSTR("Initializing Quartz display error: could not allocate display context data.\n"));
          }
        return (NULL);
      }

    aContext->connectionID    = _initDisplayConnection();
    aContext->bootImageWindowID  = (CGSWindowID  )0;
    aContext->statusWindowID  = (CGSWindowID  )0;
    aContext->safeBootWindowID= (CGSWindowID  )0;
    aContext->bootImageContext= (CGContextRef )0;
    aContext->statusContext   = (CGContextRef )0;
    aContext->progressContext = (CGContextRef )0;
    aContext->safeBootContext = (CGContextRef )0;
    aContext->progressBar     = (ProgressBarRef)NULL;

    _initBootImageContext    (aContext);
    _initStatusWindowContext (aContext);
    _initSafeBootWindowContext (aContext);

    /* set up window context */
    aContext->progressContext = CGWindowContextCreate(aContext->connectionID, aContext->statusWindowID, NULL);
    if (aContext->progressContext == NULL)
      {
        warning(CFSTR("CGWindowContextCreate failed.\n"));
        return(NULL);
      }

    if (CGSOrderWindow(aContext->connectionID, aContext->statusWindowID, kCGSOrderAbove, (CGSWindowID)0) != kCGSErrorSuccess)
      { warning(CFSTR("CGSOrderWindow failed.\n")); }

    return(aContext);
}

void _freeDisplayContext (DisplayContext aContext)
{
    if (aContext)
      {
	if (gDebugFlag) debug(CFSTR("Deallocating Quartz display context.\n"));

	if (aContext->progressBar) ProgressBarFree(aContext->progressBar);

	if (aContext->safeBootContext ) CGContextRelease(aContext->safeBootContext );
	if (aContext->statusContext   ) CGContextRelease(aContext->statusContext   );
	if (aContext->bootImageContext) CGContextRelease(aContext->bootImageContext);
	if (aContext->progressContext ) CGContextRelease(aContext->progressContext );

	if (aContext->connectionID) _closeDisplayConnection(aContext->connectionID);

	free(aContext);
      }
}

int _displayStatus (DisplayContext aDisplayContext, CFStringRef aMessage)
{
    if (aDisplayContext)
      {
	CGSConnectionID aConnectionID = aDisplayContext->connectionID;
	CGSWindowID	aWindowID     = aDisplayContext->statusWindowID;
	CGContextRef	aContext      = aDisplayContext->statusContext;

	if (aConnectionID && aWindowID && aContext)
	  {
	    CGSDisableUpdate(aConnectionID);

	    /**
	     * Erase the status area.
	     **/
	    {
              CGRect aRectangle = CGRectMake(0.0, 0.0, kStatusAreaWidth, kStatusAreaHeight - kStatusBarHeight);

              CGContextSaveGState               (aContext);
              CGContextSetCompositeOperation    (aContext, kCGCompositeCopy);
              CGContextSetRGBFillColor          (aContext, kStatusAreaColor);
              CGContextFillRect                 (aContext, aRectangle);
              CGContextRestoreGState            (aContext);
	    }

	    /**
	     * Draw text.
	     **/
	    if (aMessage)
	      {
		int   aUnitsPerEm;
		int   anIterator;
		float aScale;
		float aStringWidth = 0.0;
		char* aLanguage	   = getenv("LANGUAGE");
                char* aFontName	   = kStatusTextFont;
                
		/* Allocate mem for character, glyph and advance arrays. */
		CFIndex	 aMessageLength = CFStringGetLength(aMessage);
		UniChar* aCharacters	= (UniChar*)malloc(aMessageLength * sizeof(UniChar));
		CGGlyph* aGlyphs	= (CGGlyph*)malloc(aMessageLength * sizeof(CGGlyph));
		int*	 anAdvances	= (int*	   )malloc(aMessageLength * sizeof(int	  ));
                if (aLanguage) {
                     if (!strcmp(aLanguage, "Japanese"))
                         aFontName = "HiraKakuPro-W3";
                     else if (!strcmp(aLanguage, "zh_CN") || !strcmp(aLanguage, "SimpChinese"))
                         aFontName = "SIL-Hei-Med-Jian";
                     else if (!strcmp(aLanguage, "zh_TW") || !strcmp(aLanguage, "TradChinese"))
                         aFontName = "LiGothicMed";
                     else if (!strcmp(aLanguage, "ko") || !strcmp(aLanguage,"Korean"))
                         aFontName = "AppleGothic";
                }                                 

		/* Set up the context. */
		CGContextSaveGState	    (aContext);
		CGContextSetRGBFillColor   (aContext, kStatusTextColor);
		CGContextSelectFont (aContext, aFontName, kStatusTextFontSize, kCGEncodingMacRoman);

		/* Get the characters, glyphs and advances and calculate aStringWidth. */
		CFStringGetCharacters	   (aMessage, CFRangeMake(0, aMessageLength), aCharacters);
		CGFontGetGlyphsForUnicodes (CGContextGetFont(aContext), aCharacters, aGlyphs, aMessageLength);
		CGFontGetGlyphAdvances	   (CGContextGetFont(aContext), aGlyphs, aMessageLength, anAdvances);

		aUnitsPerEm = CGFontGetUnitsPerEm(CGContextGetFont(aContext));
		aScale	    = CGContextGetFontSize(aContext);

		/* Calculate our length. */
		for (anIterator = 0; anIterator < aMessageLength; ++anIterator)
		    aStringWidth += anAdvances[anIterator] * aScale / aUnitsPerEm;

		/* Finally - display glyphs centered in status area. */
		CGContextShowGlyphsAtPoint (aContext,
					    (kStatusAreaWidth - aStringWidth) /2.0,
					    (2.0 + (kStatusAreaHeight/2.0) - kStatusTextFontSize) / 2.0,
					    aGlyphs,
					    aMessageLength);

		/* Restore the context and free our buffers. */
		CGContextRestoreGState(aContext);

		free(aCharacters);
		free(aGlyphs	);
		free(anAdvances );
		
	      }

	    /**
	     * Flush.
	     **/
	    CGSReenableUpdate (aConnectionID);
	    CGContextFlush    (aContext);

	    return(0);
	  }
      }
    return(1);
}

int _displayProgress (DisplayContext aDisplayContext, float aPercentage)
{
    if (aDisplayContext)
      {
	CGSConnectionID aConnectionID = aDisplayContext->connectionID;
	CGSWindowID	aWindowID     = aDisplayContext->statusWindowID;
	CGContextRef	aContext      = aDisplayContext->statusContext;

	if (aConnectionID && aWindowID && aContext)
	  {
	    CGSDisableUpdate(aConnectionID);

	    /**
	     * Draw status bar.
	     **/
	    if (!aDisplayContext->progressBar)
              {
		aDisplayContext->progressBar = ProgressBarCreate(aDisplayContext->progressContext,
								 kStatusBarPosX, kStatusBarPosY,
								 kStatusBarWidth);
	      }

            if (aPercentage < 0.0) aPercentage = 0.0;
            if (aPercentage > 1.0) aPercentage = 1.0;
	    ProgressBarSetPercent (aDisplayContext->progressBar, aPercentage);

	    /**
	     * Flush.
	     **/
	    CGSReenableUpdate (aConnectionID);
	    CGContextFlush    (aContext);

	    return(0);
	  }
      }
    return(1);
}

int _displaySafeBootMsg (DisplayContext aDisplayContext, CFStringRef aMessage)
{
    if (aDisplayContext)
      {
        CGSConnectionID aConnectionID = aDisplayContext->connectionID;
        CGSWindowID     aWindowID     = aDisplayContext->safeBootWindowID;
        CGContextRef    aContext      = aDisplayContext->safeBootContext;

        if (aConnectionID && aWindowID && aContext)
          {
            CGSDisableUpdate(aConnectionID);

            if (CGSOrderWindow(aConnectionID, aWindowID, kCGSOrderAbove, (CGSWindowID)0) != kCGSErrorSuccess)
              {
                warning(CFSTR("CGSOrderWindow failed.\n"));
              }

            /**
             * Erase the status area.
             **/
            {
              CGRect aRectangle = CGRectMake(0.0, 0.0, kSafeBootAreaWidth, kSafeBootAreaHeight);

              CGContextSaveGState               (aContext);
              CGContextSetCompositeOperation    (aContext, kCGCompositeCopy);
              CGContextSetRGBFillColor          (aContext, kStatusAreaColor);
              CGContextFillRect                 (aContext, aRectangle);
              CGContextRestoreGState            (aContext);

            }

            /**
             * Draw text.
             **/
            if (aMessage)
              {
                int   aUnitsPerEm;
                int   anIterator;
                float aScale;
                float aStringWidth = 0.0;
                char* aLanguage	   = getenv("LANGUAGE");
                char* aFontName	   = kSafeBootTextFont;


                /* Allocate mem for character, glyph and advance arrays. */
                CFIndex  aMessageLength = CFStringGetLength(aMessage);
                UniChar* aCharacters    = (UniChar*)malloc(aMessageLength * sizeof(UniChar));
                CGGlyph* aGlyphs        = (CGGlyph*)malloc(aMessageLength * sizeof(CGGlyph));
                int*     anAdvances     = (int*	   )malloc(aMessageLength * sizeof(int	  ));
                if (aLanguage) {
                    if (!strcmp(aLanguage, "Japanese"))
                        aFontName = "HiraKakuPro-W3";
                    else if (!strcmp(aLanguage, "zh_CN") || !strcmp(aLanguage, "SimpChinese"))
                        aFontName = "SIL-Hei-Med-Jian";
                    else if (!strcmp(aLanguage, "zh_TW") || !strcmp(aLanguage, "TradChinese"))
                        aFontName = "LiGothicMed";
                    else if (!strcmp(aLanguage, "ko") || !strcmp(aLanguage,"Korean"))
                        aFontName = "AppleGothic";
                }                                 


                /* Set up the context. */
                CGContextSaveGState             (aContext);
                CGContextSetRGBFillColor        (aContext, kSafeBootTextColor);
                CGContextSelectFont             (aContext, aFontName, kSafeBootTextFontSize, kCGEncodingMacRoman);
		
                /* Get the characters, glyphs and advances and calculate aStringWidth. */
                CFStringGetCharacters           (aMessage, CFRangeMake(0, aMessageLength), aCharacters);
                CGFontGetGlyphsForUnicodes      (CGContextGetFont(aContext), aCharacters, aGlyphs, aMessageLength);
                CGFontGetGlyphAdvances          (CGContextGetFont(aContext), aGlyphs, aMessageLength, anAdvances);

                aUnitsPerEm = CGFontGetUnitsPerEm(CGContextGetFont(aContext));
                aScale      = CGContextGetFontSize(aContext);

                /* Calculate our length. */
                for (anIterator = 0; anIterator < aMessageLength; ++anIterator)
                    aStringWidth += anAdvances[anIterator] * aScale / aUnitsPerEm;

                /* Finally - display glyphs centered in status area. */
                CGContextShowGlyphsAtPoint (aContext,
		                            (kSafeBootAreaWidth - aStringWidth) /2.0,
                                            (2.0 + (kSafeBootAreaHeight/2.0) - kSafeBootTextFontSize) / 2.0,
                                            aGlyphs,
                                            aMessageLength);
		
                /* Restore the context and free our buffers. */
                CGContextRestoreGState(aContext);

                free(aCharacters);
                free(aGlyphs	);
                free(anAdvances );

              }
            /**
             * Flush.
             **/
            CGSReenableUpdate (aConnectionID);
            CGContextFlush    (aContext);

            return(0);
          }
      }
    return(1);
}


