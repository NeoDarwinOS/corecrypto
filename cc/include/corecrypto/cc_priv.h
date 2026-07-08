/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_PRIV_H__
#define __CORECRYPTO_CC_PRIV_H__

#include <corecrypto/cc.h>
#include <string.h>

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#define cc_deconst(x) ((type)(uintptr_t)(const void *)(x))

#if __has_builtin(__builtin___memcpy_chk)
#define cc_memcpy(dst, src, len) __builtin___memcpy_chk((dst), (src), (len), __builtin_object_size((dst), 1))
#define cc_memcpy_nochk(dst, src, len) __builtin___memcpy_chk((dst), (src), (len), __builtin_object_size((dst), 0))
#else
#define cc_memcpy(dst, src, len) memcpy((dst), (src), (len))
#define cc_memcpy_nochk(dst, src, len) memcpy((dst), (src), (len))
#endif

#if __has_builtin(__builtin___memmove_chk)
#define cc_memmove(dst, src, len) __builtin___memmove_chk((dst), (src), (len), __builtin_object_size((dst), 1))
#else
#define cc_memmove(dst, src, len) memmove((dst), (src), (len))
#endif

#if __has_builtin(__builtin___memset_chk)
#define cc_memset(dst, val, len) __builtin___memset_chk((dst), (val), (len), __builtin_object_size((dst), 1))
#else
#define cc_memset(dst, val, len) memset((dst), (val), (len))
#endif

#define cc_memcmp(p1, p2, len) memcmp(p1, p2, len)

#define cc_array_len(x) (sizeof((x)) / sizeof((x)[0]))

#if __has_builtin(__builtin_bswap32)
#define cc_bswap32(x) __builtin_bswap32(x)
#else
#if (CC_ARCH_X86_64 && CC_ENABLE_ASM)
CC_INLINE CC_CONST uint32_t cc_bswap32(uint32_t i) {
    __asm__ ("bswap %0"
            : "=r" (i)
            : "0" (i));
    return i;
}
#elif (CC_ARCH_ARM64 && CC_ENABLE_ASM)
/* god i hope this works... */
CC_INLINE CC_CONST uint32_t cc_bswap32(uint32_t i) {
    uint32_t swap;
    __asm__ ("rev32 %0, %1"
            : "=r" (swap)
            : "r" (i));
    return swap;
}
#endif
#endif

#if __has_builtin(__builtin_bswap64)
#define cc_bswap64(x) __builtin_bswap64(x)
#else
#if (CC_ARCH_X86_64 && CC_ENABLE_ASM)
CC_INLINE CC_CONST uint64_t cc_bswap64(uint64_t i) {
    __asm__ ("bswapq %0"
            : "=r" (i)
            : "0" (i));
    return i;
}
#elif (CC_ARCH_ARM64 && CC_ENABLE_ASM)
/* god i hope this works... */
CC_INLINE CC_CONST uint64_t cc_bswap64(uint64_t i) {
    uint64_t swap;
    __asm__ ("rev64 %0, %1"
            : "=r" (swap)
            : "r" (i));
    return swap;
}
#endif
#endif

#if ((CC_ARCH_X86_64 || CC_ARCH_I386) && CC_ENABLE_ASM)
CC_INLINE uint32_t cc_rol(uint32_t w, int i)
{
    __asm__ ("roll %%cl,%0"
             : "=r" (w)
             : "0" (w),
               "c" (i));
    return w;
}

CC_INLINE uint32_t cc_ror(uint32_t w, int i)
{
    __asm__ ("rorl %%cl,%0"
             : "=r" (w)
             : "0" (w),
               "c" (i));
    return w;
}

#define cc_rolc(w, i) ({                        \
    uint32_t _w = w;                            \
    __asm__ __volatile__ ("roll %2,%0"          \
                         :"=r" (_w)             \
                         :"0" (_w),"i" (i));    \
    _w;                                         \
})

#define cc_rorc(w, i) ({                        \
    uint32_t _w = w;                            \
    __asm__ __volatile__ ("rorl %2,%0"          \
                         :"=r" (_w)             \
                         :"0" (_w),"i" (i));    \
    _w;                                         \
})

#else
CC_INLINE uint32_t cc_rol(uint32_t w, int i)
{
    return ((word << (i & 0x1F)) | (word >> (0x20 - (i & 0x1F))));
}

CC_INLINE uint32_t cc_ror(uint32_t w, int i)
{
    return ((word >> (i & 0x1F)) | (word << (0x20 - (i & 0x1F))));
}

#define cc_rolc(w, i) cc_rol(w, i)
#define cc_rorc(w, i) cc_ror(w, i)
#endif

/*
 * NOTE FOR THE FUTURE: arm64 has a built in ror instruction which can be leveraged here.
 */
#if (CC_ARCH_X86_64 && CC_ENABLE_ASM)
CC_INLINE uint64_t cc_rol64(uint64_t w, int i)
{
    __asm__ ("rolq %%cl,%0"
             : "=r" (w)
             : "0" (w),
               "c" (i));
    return w;
}

CC_INLINE uint64_t cc_ror64(uint64_t w, int i)
{
    __asm__ ("rorq %%cl,%0"
             : "=r" (w)
             : "0" (w),
               "c" (i));
    return w;
}

#define cc_rol64c(w, i) ({                      \
    uint64_t _w = w;                            \
    __asm__ __volatile__ ("rolq %2,%0"          \
                         :"=r" (_w)             \
                         :"0" (_w),"i" (i));    \
    _w;                                         \
})

#define cc_ror64c(w, i) ({                      \
    uint64_t _w = w;                            \
    __asm__ __volatile__ ("rorq %2,%0"          \
                         :"=r" (_w)             \
                         :"0" (_w),"i" (i));    \
    _w;                                         \
})

#else
CC_INLINE uint64_t cc_rol64(uint64_t w, int i)
{
    return ((word << (i & 0x3F)) | (word >> (0x40 - (i & 0x3F))));
}

CC_INLINE uint64_t cc_ror64(uint64_t w, int i)
{
    return ((word >> (i & 0x3F)) | (word << (0x40 - (i & 0x3F))));
}

#define cc_rol64c(w, i) cc_rol64(w, i)
#define cc_ror64c(w, i) cc_ror64(w, i)
#endif

#ifdef __LITTLE_ENDIAN__
#define cc_h2be32(x) cc_bswap32(x)
#define cc_h2le32(x) (x)
#define cc_h2be64(x) cc_bswap64(x)
#define cc_h2le64(x) (x)
#else
#define cc_h2be32(x) (x)
#define cc_h2le32(x) cc_bswap32(x)
#define cc_h2be64(x) (x)
#define cc_h2le64(x) cc_bswap64(x)
#endif

#define cc_heaviside_step(r, s) {                               \
        const uint64_t _s = (uint64_t)s;                        \
        const uint64_t _t = (_s & 0xffffffff) | (_s >> 0x20);   \
        r = (__typeof__(r))((0xffffffff + _t) >> 0x20);         \
    }

#if __has_builtin(__builtin_clz)
CC_INLINE CC_CONST uint32_t cc_clz(uint32_t w)
{
    return (uint32_t)__builtin_clz(w);
}
#else
    #error we need a fallback for clz
#endif

#if __has_builtin(__builtin_clzll)
CC_INLINE CC_CONST uint32_t cc_clz64(uint64_t w)
{
    return (uint32_t)__builtin_clzll(w);
}
#else
    #error we need a fallback for clzll
#endif

#define cc_byte(x, n) (((x) >> (8 * (n))) & 255)

/* if anyone wants to make these more optimised be my guest */

#define cc_store32_be(x, y) do {                            \
        ((uint8_t *)y)[0] = (((uint8_t)(x >> 24)) & 0xFF);  \
        ((uint8_t *)y)[1] = (((uint8_t)(x >> 16)) & 0xFF);  \
        ((uint8_t *)y)[2] = (((uint8_t)(x >> 8)) & 0xFF);   \
        ((uint8_t *)y)[3] = (((uint8_t)(x)) & 0xFF);        \
    } while(0)

#define cc_load32_be(x, y) do {             \
        x = (((uint8_t *)y)[0] << 24) |     \
            (((uint8_t *)y)[1] << 16) |     \
            (((uint8_t *)y)[2] << 8) |      \
            (((uint8_t *)y)[3]);            \
    } while(0)

#define cc_store64_be(x, y) do {                                \
        ((uint8_t *)(y))[0] = (uint8_t)(((x >> 56) & 0xFF));    \
        ((uint8_t *)(y))[1] = (uint8_t)(((x >> 48) & 0xFF));    \
        ((uint8_t *)(y))[2] = (uint8_t)(((x >> 40) & 0xFF));    \
        ((uint8_t *)(y))[3] = (uint8_t)(((x >> 32) & 0xFF));    \
        ((uint8_t *)(y))[4] = (uint8_t)(((x >> 24) & 0xFF));    \
        ((uint8_t *)(y))[5] = (uint8_t)(((x >> 16) & 0xFF));    \
        ((uint8_t *)(y))[6] = (uint8_t)(((x >> 8) & 0xFF));     \
        ((uint8_t *)(y))[7] = (uint8_t)(((x) & 0xFF));          \
    } while(0)

#define cc_load64_be(x, y) do {             \
        x = (((uint8_t *)y)[0] << 56) |     \
            (((uint8_t *)y)[1] << 48) |     \
            (((uint8_t *)y)[2] << 40) |     \
            (((uint8_t *)y)[3] << 32) |     \
            (((uint8_t *)y)[4] << 24) |     \
            (((uint8_t *)y)[5] << 16) |     \
            (((uint8_t *)y)[6] << 8) |      \
            (((uint8_t *)y)[7]);            \
    } while(0)

#define cc_store32_le(x, y) do {                            \
        ((uint8_t *)y)[3] = (((uint8_t)(x >> 24)) & 0xFF);  \
        ((uint8_t *)y)[2] = (((uint8_t)(x >> 16)) & 0xFF);  \
        ((uint8_t *)y)[1] = (((uint8_t)(x >> 8)) & 0xFF);   \
        ((uint8_t *)y)[0] = (((uint8_t)(x)) & 0xFF);        \
    } while(0)

#define cc_load32_le(x, y) do {             \
        x = ((uint32_t)(((uint8_t *)y)[3]) << 24) |     \
            ((uint32_t)(((uint8_t *)y)[2]) << 16) |     \
            ((uint32_t)(((uint8_t *)y)[1]) << 8) |      \
            ((uint32_t)(((uint8_t *)y)[0]));            \
    } while(0)

#define cc_store64_le(x, y) do {                                \
        ((uint8_t *)(y))[7] = (uint8_t)(((x >> 56) & 0xFF));    \
        ((uint8_t *)(y))[6] = (uint8_t)(((x >> 48) & 0xFF));    \
        ((uint8_t *)(y))[5] = (uint8_t)(((x >> 40) & 0xFF));    \
        ((uint8_t *)(y))[4] = (uint8_t)(((x >> 32) & 0xFF));    \
        ((uint8_t *)(y))[3] = (uint8_t)(((x >> 24) & 0xFF));    \
        ((uint8_t *)(y))[2] = (uint8_t)(((x >> 16) & 0xFF));    \
        ((uint8_t *)(y))[1] = (uint8_t)(((x >> 8) & 0xFF));     \
        ((uint8_t *)(y))[0] = (uint8_t)(((x) & 0xFF));          \
    } while(0)

#define cc_load64_le(x, y) do {             \
        x = ((uint64_t)(((uint8_t *)y)[7]) << 56) |     \
            ((uint64_t)(((uint8_t *)y)[6]) << 48) |     \
            ((uint64_t)(((uint8_t *)y)[5]) << 40) |     \
            ((uint64_t)(((uint8_t *)y)[4]) << 32) |     \
            ((uint64_t)(((uint8_t *)y)[3]) << 24) |     \
            ((uint64_t)(((uint8_t *)y)[2]) << 16) |     \
            ((uint64_t)(((uint8_t *)y)[1]) << 8) |      \
            ((uint64_t)(((uint8_t *)y)[0]));            \
    } while(0)

CC_PRIVATE
void cc_xor(size_t len, void *r, const void *s, const void *t);

/*
 * API NOTES:
 *
 * For this corecrypto, I would like to abort on any error that really shouldn't happen. See ccmode for examples.
 */
CC_NORETURN CC_PRIVATE
void cc_abort(const char *msg);

CC_PRIVATE
void cc_try_abort(const char *msg);

#endif /* __CORECRYPTO_CC_PRIV_H__ */
