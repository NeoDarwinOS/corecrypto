/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_KEXT_IF_H__
#define __CORECRYPTO_KEXT_IF_H__

#include <mach/mach_types.h>
#include <corecrypto/cc_debug.h>

#if defined (__has_include)
    #if __has_include(<libkern/crypto/register_crypto.h>)
        #include <libkern/crypto/register_crypto.h>
        #define __CC_KEXT_HAS_SYSTEM_HEADER__   1
    #endif
#endif // defined (__has_include)

#ifndef __CC_KEXT_HAS_SYSTEM_HEADER__
    #define __CC_KEXT_HAS_SYSTEM_HEADER__ 0

    #include <EXTERNAL_HEADERS/libkern/crypto/register_crypto.h>
#endif

#if !__CC_KEXT_HAS_SYSTEM_HEADER__
#warning Not using registration interface from SDK. This might be iffy.
#endif

#endif /* __CORECRYPTO_KEXT_IF_H__ */
