/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_ABSOLUTE_TIME_H__
#define __CORECRYPTO_CC_ABSOLUTE_TIME_H__

#include <corecrypto/cc_config.h>
#include <stdint.h>

#if CC_PLATFORM_XNU
    #include <mach/mach_time.h>
    #include <kern/clock.h>

    CC_INLINE uint64_t cc_absolute_time(void) {
        return mach_absolute_time();
    }
#elif CC_PLATFORM_DARWIN
    #include <mach/mach_time.h>
    
    CC_INLINE uint64_t cc_absolute_time(void) {
        return mach_absolute_time();
    }
#elif CC_PLATFORM_LINUX

//
// big fat todo here for later.
//

#elif CC_PLATFORM_WINDOWS
    #include <windows.h>
    #include <profileapi.h>

    CC_INLINE uint64_t cc_absolute_time(void) {
        LARGE_INTEGER count;
        QueryPerformanceCounter(&count);
        return count.QuadPart;
    }
#else
    #error unsupported platform
#endif

#endif /* __CORECRYPTO_CC_ABSOLUTE_TIME_H__ */
