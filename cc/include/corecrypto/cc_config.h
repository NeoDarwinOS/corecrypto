/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_CONFIG_H__
#define __CORECRYPTO_CC_CONFIG_H__

/* If we have it, include TargetConditionals. Is this redundant given the later platform checks? */
#if defined(__has_include)
    #if __has_include(<TargetConditionals.h>)
        #include <TargetConditionals.h>
    #endif
#endif

/*
 * The external build environment should provide one of the following (on non-kernel platforms):
 *     - CC_STATIC_LIBRARY
 *     - CC_SHARED_LIBRARY
 */

#if defined(DEBUG) && DEBUG
    #define CORECRYPTO_DEBUG    1
#else
    #define CORECRYPTO_DEBUG    0
#endif

#if defined (KERNEL) && KERNEL
    #define CC_PLATFORM_XNU     1
#endif

#if defined (__APPLE__) && defined (__MACH__) && !CC_PLATFORM_XNU
    #define CC_PLATFORM_DARWIN  1
#endif

#if defined (__linux__)
    #define CC_PLATFORM_LINUX   1
#endif

#if defined (__x86_64__) && __x86_64__
    #define CC_ARCH_X86_64  1
#elif defined (__arm64__) && __arm64__
    #define CC_ARCH_ARM64   1
#elif defined (__arm__) && __arm__
    #define CC_ARCH_ARM     1

    #if defined (__ARM_ARCH_7A__) || defined (__ARM_ARCH_7S__) || defined (__ARM_ARCH_7F__) || defined (__ARM_ARCH_7K__)
        #define CC_ARCH_ARMV7   1
    #endif

    #if defined (__ARM_ARCH_6K__)
        #define CC_ARCH_ARMV6K  1
    #endif

    #if defined (__ARM_ARCH_6__)
        #define CC_ARCH_ARMV6   1
    #endif
#elif defined (__i386__) && __i386__
    #define CC_ARCH_I386     1
#endif

/* Configure the size of cc units, which is usually the register size. */
#if CC_ARCH_X86_64 || CC_ARCH_ARM64
    #define CCN_UNIT_SIZE   8
#elif CC_ARCH_I386 || CC_ARCH_ARM
    #define CCN_UNIT_SIZE   4
#else
    #error unsupported architecture
#endif

#if !defined(CC_ENABLE_ASM)
    #if CC_PLATFORM_XNU || CC_PLATFORM_DARWIN || CC_PLATFORM_LINUX
        #define CC_ENABLE_ASM   1
    #else
        #define CC_ENABLE_ASM   0
    #endif
#endif // !defined(CC_ENABLE_ASM)

#if CC_PLATFORM_XNU && CC_ENABLE_ASM
    /* Under XNU/Kernel we need to save and restore registers ourself */
    #define CC_ENABLE_SAVE_REGISTERS_ASM    1
#else
    #define CC_ENABLE_SAVE_REGISTERS_ASM    0
#endif

/* This is specific to a certain Darwin variant. I wonder which one that is. */
#if defined(__has_include)
    #if __has_include(<System/i386/cpu_capabilities.h>)
        #include <System/i386/cpu_capabilities.h>

        #if defined (kHasSHA)
            #define CC_INTEL_HAS_SHA_BIT        1
        #endif

        #if defined (kHasSHA512)
            #define CC_INTEL_HAS_SHA512_BIT     1
        #endif
    #endif // __has_include(<System/i386/cpu_capabilities.h>)
#endif // defined(__has_include)

#if defined (__has_attribute)
    #if __has_attribute(noreturn)
        #define CC_NORETURN __attribute__((__noreturn__))
    #else
        #define CC_NORETURN
    #endif

    #if __has_attribute(nothrow)
        #define CC_NOTHROW __attribute__((__nothrow__))
    #else
        #define CC_NOTHROW
    #endif

    #if __has_attribute(nonnull)
        #define CC_NONNULL(x) __attribute__((__nonnull__ x ))
        #define CC_NONNULL_ALL __attribute__((__nonnull__))
    #else
        #define CC_NONNULL(x)
        #define CC_NONNULL_ALL
    #endif
#else

#endif

#endif /* __CORECRYPTO_CC_CONFIG_H__ */
