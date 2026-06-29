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

/*
 * API NOTES:
 *
 * The symbols in the SDK's .tbd are actually just the symbols it exports nicely, which gives us a reference point as
 * for what symbols are required to build in each version.
 *
 * Apple likes to freeball their own crypto library, which means that each release sucks in terms of
 * compatibility with prior versions.
 *
 * The overall ABI seems to have stabilized again, but this project targets Darwin 19 and 20 compatibility, not 21 and newer,
 * which have... issues, to say the least.
 *
 * Darwin 21 as a goal would be nice, but there are other cornerstones that need to be achieved before kernelspace work
 * can begin properly.
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
    #define CC_UNIT_SIZE    8
#elif CC_ARCH_I386 || CC_ARCH_ARM
    #define CC_UNIT_SIZE    4
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
    #if __has_attribute(const)
        #define CC_CONST __attribute__((__const__))
    #else
        #define CC_CONST
    #endif

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

    #if __has_attribute(pure)
        #define CC_PURE __attribute__((__pure__))
    #else
        #define CC_PURE
    #endif

    #if __has_attribute(mode)
        #if CC_ARCH_X86_64 || CC_ARCH_ARM64
            #define CC_UNIT_ALLOW_UINT128_DUNIT 1
        #else
            #define CC_UNIT_ALLOW_UINT128_DUNIT 0
        #endif
    #else
        #define CC_UNIT_ALLOW_UINT128_DUNIT 0
    #endif

    #if __has_attribute(visibility)
        #define CC_PRIVATE extern __attribute__((visibility("hidden")))
        #define CC_EXPORT extern __attribute__((visibility("default")))
    #else
        #define CC_PRIVATE
        #define CC_EXPORT
    #endif
#else
    #define CC_CONST
    #define CC_NORETURN
    #define CC_NOTHROW
    #define CC_NONNULL(x)
    #define CC_NONNULL_ALL
    #define CC_PURE
    #define CC_UNIT_ALLOW_UINT128_DUNIT 0
    #define CC_PRIVATE
    #define CC_EXPORT
#endif

#if CC_UNIT_SIZE == 8
    #if __GNUC__
        #define cc_aligned(x) __attribute__((aligned((x))))
    #else
        #error unsupported compiler
    #endif
#else
    #if __GNUC__
        #define cc_aligned(x) __attribute__ ((aligned((x) > 8 ? 8 : (x))))
    #else
        #error unsupported compiler
    #endif
#endif

#if defined __BIGGEST_ALIGNMENT__
    #define CC_MAX_ALIGNMENT __BIGGEST_ALIGNMENT__
#else
    #define CC_MAX_ALIGNMENT 16
#endif

#define CC_INLINE static inline

#if __cplusplus
    #define CC_BEGIN_DECLS extern "C" {
    #define CC_END_DECLS }
#else
    #define CC_BEGIN_DECLS
    #define CC_END_DECLS
#endif

#ifndef CC_SMALL_CODE
#define CC_SMALL_CODE 0
#endif

#endif /* __CORECRYPTO_CC_CONFIG_H__ */
