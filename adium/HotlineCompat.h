/* purple-hotline for Adium: one source for Adium 1.5 (64-bit, Objective-C 2.0) and
 * Adium 1.3 on Mac OS X 10.4 (PowerPC/Intel, gcc 4.0, Objective-C 1.0): no dot syntax
 * or fast enumeration here, and NSInteger where the 10.4 SDK has none. MIT license. */
#ifndef HOTLINE_COMPAT_H
#define HOTLINE_COMPAT_H
#import <Foundation/Foundation.h>
#if !defined(NSINTEGER_DEFINED) && !defined(NSIntegerMax)
typedef int NSInteger;
typedef unsigned int NSUInteger;
#define NSINTEGER_DEFINED 1
#endif
#endif
