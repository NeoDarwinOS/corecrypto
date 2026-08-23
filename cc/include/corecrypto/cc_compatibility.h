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

//
// Brief overview:
// These macros are intended to hint to the build time environment what features should be enabled or not.
//
// This is particularly relevant for our kernel interface.
//

#if __has_include(<AvailabilityVersions.h>)
    #include <AvailabilityVersions.h>
#endif

//
// Currently, the project targets Mac OS X 10.15 and higher.
//
// This could later change if need be, say to bootstrap the PD 17.4 image.
//
// These macros rely on the fact that we use Mac OS X as the base target. In the future, if such a change were made to
// the target triple where we no longer used PLATFORM_MACOS and __MAC_OS_X_VERSION_MIN_REQUIRED, it would break this.
//
#if !defined(__MAC_10_10)
    #define __MAC_10_10 101000
#endif

#if !defined(__MAC_10_11)
    #define __MAC_10_11 101100
#endif

#if !defined(__MAC_10_12)
    #define __MAC_10_12 101200
#endif

#if !defined(__MAC_10_13)
    #define __MAC_10_13 101300
#endif

#if !defined(__MAC_10_14)
    #define __MAC_10_14 101400
#endif

#if !defined(__MAC_10_14_6)
    #define __MAC_10_14_6 101406
#endif

#if !defined(__MAC_10_15)
    #define __MAC_10_15 101500
#endif

#if !defined(__MAC_11_0)
    #define __MAC_11_0  110000
#endif

#if !defined(__MAC_11_1)
    #define __MAC_11_1  110100
#endif

#if !defined(__MAC_12_0)
    #define __MAC_12_0  120000
#endif

#if !defined(__MAC_13_0)
    #define __MAC_13_0  130000
#endif

#if !defined(__MAC_13_3)
    #define __MAC_13_3  130300
#endif

#if !defined(__MAC_14_0)
    #define __MAC_14_0  140000
#endif

#if !defined(__MAC_15_0)
    #define __MAC_15_0  150000
#endif

//
// Apple briefly used 16.0 in source code.
//
#if !defined(__MAC_16_0)
    #define __MAC_16_0  160000
#endif

#if !defined(__MAC_26_0)
    #define __MAC_26_0  260000
#endif

//
// Does Xcode even let you compile for x86 after 27.0
//
#if !defined(__MAC_27_0)
    #define __MAC_27_0  270000
#endif

//
// just in case...
//
#if !defined(__MAC_28_0)
    #define __MAC_28_0  280000
#endif

#if !defined (__MAC_OS_X_VERSION_MIN_REQUIRED)
    #define __MAC_OS_X_VERSION_MIN_REQUIRED __MAC_10_15
#endif

//
// Apple hasn't dramatically updated their KPIs between minor versions yet.
//
// USAGE:
// The first parameters is explicitly the floor of the minimum version, ex: __MAC_10_15,
// the second parameter is ALWAYS the cutoff version.
//
// Example:
// __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_15, __MAC_13_0) will return true for any macOS deployment target between
// 10.15 and the value of 12.99.99
//
#define __CC_DEPLOYMENT_IS_IN_RANGE(start, ceiling) ((__MAC_OS_X_VERSION_MIN_REQUIRED >= (start)) && \
                                                        __MAC_OS_X_VERSION_MIN_REQUIRED < (ceiling))

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_15, __MAC_11_0)
    #define __CC_COMPATIBILITY_DARWIN_19 1
#else
    #define __CC_COMPATIBILITY_DARWIN_19 0
#endif

//
// Removed Kernel Interfaces (since Darwin 19):
//  ccblowfish_ecb_encrypt
//  ccblowfish_ecb_decrypt
//  cccast_ecb_encrypt
//  cccast_ecb_decrypt
//  ccpad_xts_encrypt_fn
//  ccpad_xts_decrypt_fn
//  ccrc4_info
//
#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_11_0, __MAC_12_0)
    #define __CC_COMPATIBILITY_DARWIN_20 1
#else
    #define __CC_COMPATIBILITY_DARWIN_20 0
#endif

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_12_0, __MAC_13_0)
    #define __CC_COMPATIBILITY_DARWIN_21 1
#else
    #define __CC_COMPATIBILITY_DARWIN_21 0
#endif

//
// Added kernel interface functions:
//  digest_ctx_size_fn
//  digest_init_fn
//  digest_update_fn
//  digest_final_fn
//  digest_fn
//
//  hmac_ctx_size_fn
//  hmac_init_fn
//  hmac_update_fn
//  hmac_final_generate_fn
//  hmac_final_verify_fn
//  hmac_generate_fn
//  hmac_verify_fn
//
#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_14_0)
    #define __CC_COMPATIBILITY_DARWIN_22 1
#else
    #define __CC_COMPATIBILITY_DARWIN_22 0
#endif

//
// Added kernel interface functions:
//  random_generate_fn
//  random_uniform_fn
//  random_kmem_ctx_size_fn
//  random_kmem_init_fn
//
#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_3, __MAC_14_0)
    #define __CC_COMPATIBILITY_DARWIN_22_4 1
#else
    #define __CC_COMPATIBILITY_DARWIN_22_4 0
#endif

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_14_0, __MAC_15_0)
    #define __CC_COMPATIBILITY_DARWIN_23 1
#else
    #define __CC_COMPATIBILITY_DARWIN_23 0
#endif

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_15_0, __MAC_16_0)
    #define __CC_COMPATIBILITY_DARWIN_24 1
#else
    #define __CC_COMPATIBILITY_DARWIN_24 0
#endif

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_26_0, __MAC_27_0)
    #define __CC_COMPATIBILITY_DARWIN_25 1
#else
    #define __CC_COMPATIBILITY_DARWIN_25 0
#endif

//
// Yes. They skipped Darwin 26 and went straight to 27.
//
#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_27_0, __MAC_28_0)
    #define __CC_COMPATIBILITY_DARWIN_27 1
#else
    #define __CC_COMPATIBILITY_DARWIN_27 0
#endif

#define CC_COMPATIBILITY_TARGETS(x) (__CC_COMPATIBILITY_##x == 1)

#endif /* __CORECRYPTO_CC_COMPATIBILITY_H__ */
