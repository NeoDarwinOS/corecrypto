/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_H__
#define __CORECRYPTO_CC_H__

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_error.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#if CORECRYPTO_DEBUG
    #if CC_PLATFORM_XNU
        #include <kern/assert.h>
    #else
        #include <assert.h>
    #endif

    #define cc_assert(args) assert(args)
#else
    #define cc_assert(args)
#endif

#define cc_concat_(a, b) a##b
#define cc_concat(a, b) cc_concat_(a, b)

/* static assertion macro */
#define cc_static_assert(cond, msg) enum { cc_concat(cc_static_assert_, __COUNTER__) = 1 / (int)(!!(cond)) }

#define cc_aligned_struct(alignment) \
    typedef struct { \
        uint8_t byte[ alignment ]; \
    } cc_aligned(alignment)

#define cc_pad_align(size) ((size + CC_MAX_ALIGNMENT - 1) & (~(CC_MAX_ALIGNMENT - 1)))

/* These macros rely on the appropriate pointer sizes being the same as cc_unit. */
#define cc_ctx_n(type, size) ((size + sizeof(type) - 1) / sizeof(type))
#define cc_ctx_sizeof(type, size) sizeof(type[cc_ctx_n(type, size)])

#define cc_ctx_decl(type, size, name) type name [cc_ctx_n(type, size)]

/*
 * The following are functions that are supposed to be delcared by this header.
 */

/*!
 * @function    cc_clear
 *              Zero-fill a chunk of memory
 *
 * @param       len
 *              The length of the memory chunk
 *
 * @param       mem
 *              Pointer to the memory chunk
 */
CC_EXPORT CC_NONNULL((2))
void cc_clear(size_t len, void *mem);

CC_EXPORT CC_NONNULL((2, 3))
void cc_copy(size_t len, void *dst, const void *src);

CC_EXPORT CC_NONNULL((2, 3))
int cc_cmp_safe(size_t len, const void *p1, const void *p2);

#define cc_swap(S, T) do {                          \
        volatile __typeof__(S) _cc_swap_tmp = S;    \
        S = T;                                      \
        T = _cc_swap_tmp;                           \
        _cc_swap_tmp = 0;                           \
    } while (0)

#define cc_max(S, T) ({                                 \
        __typeof__(S) _cc_max_s = S;                    \
        __typeof__(T) _cc_max_t = T;                    \
        _cc_max_s > _cc_max_t ? _cc_max_s : _cc_max_t;  \
    })

#define cc_min(S, T) ({                                 \
        __typeof__(S) _cc_min_s = S;                    \
        __typeof__(T) _cc_min_t = T;                    \
        _cc_min_s <= _cc_min_t ? _cc_min_s : _cc_min_t; \
    })

#define cc_ceiling(a,b) (((a) + ((b) - 1)) / (b))

/*
 * Declare cc_unit here rather than in ccn, prevents any potential header dependency cycle
 */
typedef uint8_t cc_byte;
typedef size_t  cc_size;

#if CC_UNIT_SIZE == 8
typedef uint64_t cc_unit;
typedef int64_t cc_int;

#if CC_UNIT_ALLOW_UINT128_DUNIT
typedef unsigned cc_dunit __attribute__((mode(TI)));
typedef signed cc_dint __attribute__((mode(TI)));
#else
typedef struct cc_dunit {
    uint64_t lo;
    uint64_t hi;
} cc_dunit;

typedef struct cc_dint {
    uint64_t lo;
    uint64_t hi;
} cc_dint;
#endif

#define CC_LOG2_BITS_PER_UNIT   6
#define CC_UNIT_C(x) UINT64_C(x)
#elif CC_UNIT_SIZE == 4
typedef uint32_t cc_unit;
typedef uint64_t cc_dunit;
typedef int32_t cc_int;
typedef int64_t cc_dint;

#define CC_LOG2_BITS_PER_UNIT   5
#define CC_UNIT_C(x) UINT32_C(x)
#endif

/* CC_UNIT_BITS = bytes * bits per byte */
#define CC_UNIT_BITS            (sizeof(cc_unit) * 8)
#define CC_UNIT_MASK            ((cc_unit)~0)
#define CC_UNIT_LOWER_HALF_MASK ((CC_UNIT_MASK) >> (CC_UNIT_BITS/2))
#define CC_UNIT_UPPER_HALF_MASK (~CC_UNIT_LOWER_HALF_MASK)

#endif /* __CORECRYPTO_CC_H__ */
