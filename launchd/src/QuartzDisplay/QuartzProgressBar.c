/**
 * QuartzProgressBar.c - Quartz Progress Bar
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
 * Draws the progress bar using CoreGraphics (Quartz).
 **/

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <CoreGraphics/CGContext.h>

/*
 * This is an opaque (void *) pointer in QuartzProgressBar.h.
 * The following definition is private to this file.
 */
typedef struct ProgressBar
{
    CGContextRef   context;
    CGRect         frame;
    CGImageRef     fillImage;
    float          percent;
    int            offset;
    int            active;
    pthread_t      thread;
} *ProgressBarRef;
#define _QuartzProgressBar_C_
#include "QuartzProgressBar.h"

#include "QuartzProgressBarData.c"

static void _ProgressBarDrawBackground (ProgressBarRef aProgressBar)
{
    CGColorSpaceRef aColorspace = CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef aDataProvider;
    CGImageRef endCap = NULL, barBackground = NULL;
    float x, y, w, xcur;

    x = aProgressBar->frame.origin.x;
    y = aProgressBar->frame.origin.y;
    w = aProgressBar->frame.size.width;

    /* Using only 1/4th the image on each end cap may seem like a waste, */
    /* but is necessary so that shadows do not overlap.                  */

    /* Left endcap */
    CGContextSaveGState    (aProgressBar->context);
    CGContextClipToRect    (aProgressBar->context, CGRectMake(x, y, gEndCapWidth / 2.0, gEndCapHeight));

    aDataProvider = CGDataProviderCreateWithData(NULL, &gEndcapData, 4 * gEndCapWidth * gEndCapHeight, NULL);
    if (aDataProvider)
      {
        endCap = CGImageCreate(gEndCapWidth,
                               gEndCapHeight,
                               8,
                               32,
                               gEndCapWidth * 4,
                               aColorspace,
                               kCGImageAlphaPremultipliedLast,
                               aDataProvider,
                               NULL,
                               0,
                               kCGRenderingIntentDefault);
        CGDataProviderRelease(aDataProvider);
      }
    if (endCap)
      {
        CGContextDrawImage (aProgressBar->context, CGRectMake(x, y, gEndCapWidth, gEndCapHeight), endCap);
      }
    CGContextRestoreGState (aProgressBar->context);

    /* Right endcap */
    CGContextSaveGState    (aProgressBar->context);
    CGContextClipToRect    (aProgressBar->context, CGRectMake(x + w - gEndCapWidth / 2.0, y, gEndCapWidth / 2.0, gEndCapHeight));

    if (endCap)
      {
        CGContextDrawImage (aProgressBar->context, CGRectMake((x + w - gEndCapWidth / 2.0) - 1.0, y, gEndCapWidth / 2.0, gEndCapHeight), endCap);
        CGImageRelease(endCap);
      }

    CGContextRestoreGState (aProgressBar->context);

    /* Bar */
    CGContextSaveGState    (aProgressBar->context);
    CGContextClipToRect    (aProgressBar->context, CGRectMake(x + gEndCapWidth / 2.0 , y, w - gEndCapWidth, gEndCapHeight));
    aDataProvider = CGDataProviderCreateWithData(NULL, &gBackfillData, 4 * gBackFillWidth * gBackFillHeight, NULL);
    if (aDataProvider)
      {
        barBackground = CGImageCreate( gBackFillWidth,
                               gBackFillHeight,
                               8,
                               32,
                               gBackFillWidth * 4,
                               aColorspace,
                               kCGImageAlphaPremultipliedLast,
                               aDataProvider,
                               NULL,
                               0,
                               kCGRenderingIntentDefault);
        CGDataProviderRelease(aDataProvider);
      }
    if (barBackground)
      {
        for (xcur = x; xcur < x + w; xcur += gBackFillWidth)
          {
            CGContextDrawImage (aProgressBar->context, CGRectMake(xcur, y, gBackFillWidth, gBackFillHeight), barBackground);
          }
        CGImageRelease(barBackground);
      }
    CGContextRestoreGState (aProgressBar->context);

    /* Clean up */
    CGContextFlush (aProgressBar->context);
    CGColorSpaceRelease (aColorspace);
}

static void _ProgressBarDraw (ProgressBarRef aProgressBar)
{
    float x, y, w, xcur;

    x = aProgressBar->frame.origin.x;
    y = aProgressBar->frame.origin.y;
    w = aProgressBar->frame.size.width;

    /**
     * Lay down the progress bar.
     **/
    CGContextSaveGState (aProgressBar->context);
    CGContextClipToRect   (aProgressBar->context,
                  CGRectMake(x + gEndCapWidth / 4.0, y + (gEndCapHeight - gFillHeight),
                               (w - gEndCapWidth / 2.0) * aProgressBar->percent, gFillHeight));
    for (xcur = x + gEndCapWidth / 4.0 - aProgressBar->offset;
         xcur < x + w - gEndCapWidth / 4.0;
         xcur += gFillWidth)
      {
        CGContextDrawImage (aProgressBar->context, CGRectMake(xcur, y + (gEndCapHeight - gFillHeight), gFillWidth, gFillHeight), aProgressBar->fillImage);
      }
    CGContextRestoreGState (aProgressBar->context);

    /* Clean up */
    CGContextFlush (aProgressBar->context);
}

/* FIXME: This should be in a public header */
extern int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);

static void *_ProgressBarBackgroundThread (void *arg)
{
    ProgressBarRef aProgressBar = (ProgressBarRef)arg;
    static const struct timespec aThirty = { 0, 1000000000 / 30};

    _ProgressBarDrawBackground (aProgressBar);

    while (aProgressBar->active)
      {
        aProgressBar->offset++;

        if (aProgressBar->offset > 15) aProgressBar->offset = 0;

        _ProgressBarDraw (aProgressBar);

        nanosleep(&aThirty, NULL);
      }

    return NULL;
}

ProgressBarRef ProgressBarCreate (CGContextRef aContext, float x, float y, float w)
{
    CGColorSpaceRef aColorspace = CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef aDataProvider;
    ProgressBarRef aProgressBar = (ProgressBarRef)malloc(sizeof(struct ProgressBar));

    aProgressBar->context           = aContext;
    aProgressBar->frame.origin.x    = x;
    aProgressBar->frame.origin.y    = y;
    aProgressBar->frame.size.width  = w;
    aProgressBar->frame.size.height = gEndCapHeight;
    aProgressBar->percent           = 0.0;
    aProgressBar->offset            = 0;
    aProgressBar->active            = 1;
    aProgressBar->fillImage         = NULL;
    aDataProvider                   = CGDataProviderCreateWithData(NULL, & gFillData, 4 * gFillWidth * gFillHeight, NULL);
    if (aDataProvider && aColorspace)
      {
        aProgressBar->fillImage     = CGImageCreate( gFillWidth,
                                           gFillHeight,
                                           8,
                                           32,
                                           gFillWidth * 4,
                                           aColorspace,
                                           kCGImageAlphaPremultipliedLast,
                                           aDataProvider,
                                           NULL,
                                           0,
                                           kCGRenderingIntentDefault);
      }

    if (aColorspace)
      {
        CGColorSpaceRelease (aColorspace);
      }
    if (aDataProvider)
      {
        CGDataProviderRelease(aDataProvider);
      }
    pthread_create (&aProgressBar->thread, NULL, _ProgressBarBackgroundThread, aProgressBar);

    return aProgressBar;
}

void ProgressBarFree (ProgressBarRef aProgressBar)
{
    aProgressBar->active = 0;
    pthread_join(aProgressBar->thread, NULL);

    if (aProgressBar->fillImage)
      {
        CGImageRelease(aProgressBar->fillImage);
      }

    free(aProgressBar);
}

void ProgressBarDisplay (ProgressBarRef aProgressBar)
{
    /**
     * Assumes that the opaque ancestor (what is underneath the bar)
     * has been redrawn, and the bar is to be drawn atop that.
     **/
    _ProgressBarDrawBackground (aProgressBar);
    _ProgressBarDraw           (aProgressBar);
}

void ProgressBarSetPercent (ProgressBarRef aProgressBar, float aPercent)
{
    aProgressBar->percent = aPercent;
}
