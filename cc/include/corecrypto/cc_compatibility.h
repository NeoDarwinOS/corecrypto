/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_COMPATIBILITY_H__
#define __CORECRYPTO_CC_COMPATIBILITY_H__

#include <corecrypto/cc_config.h>

#if __has_include(<AvailabilityVersions.h>)
    #include <AvailabilityVersions.h>
#endif

#if !defined(__MAC_10_15)
    #define __MAC_10_15 101500
#endif

#if !defined(__MAC_11_0)
    #define __MAC_11_0 110000
#endif

#if !defined(__MAC_12_0)
    #define __MAC_12_0 120000
#endif

#if !defined(__MAC_13_0)
    #define __MAC_13_0 130000
#endif

#if !defined (__MAC_OS_X_VERSION_MIN_REQUIRED)
    #define __MAC_OS_X_VERSION_MIN_REQUIRED __MAC_10_15
#endif

#if __MAC_OS_X_VERSION_MIN_REQUIRED == __MAC_10_15
    #define __CC_COMPATIBILITY_DARWIN_19 1
#else
    #define __CC_COMPATIBILITY_DARWIN_19 0
#endif

#if __MAC_OS_X_VERSION_MIN_REQUIRED == __MAC_11_0
    #define __CC_COMPATIBILITY_DARWIN_20 1
#else
    #define __CC_COMPATIBILITY_DARWIN_20 0
#endif

#if __MAC_OS_X_VERSION_MIN_REQUIRED == __MAC_12_0
    #define __CC_COMPATIBILITY_DARWIN_21 1
#else
    #define __CC_COMPATIBILITY_DARWIN_21 0
#endif

#if __MAC_OS_X_VERSION_MIN_REQUIRED == __MAC_13_0
    #define __CC_COMPATIBILITY_DARWIN_22 1
#else
    #define __CC_COMPATIBILITY_DARWIN_22 0
#endif

#define CC_COMPATIBILITY_TARGETS(x) (__CC_COMPATIBILITY_##x == 1)

#endif /* __CORECRYPTO_CC_COMPATIBILITY_H__ */
