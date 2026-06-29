/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Code adapted from LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/ccsha1_internal.h>

#define F0(x, y, z) (z ^ (x & (y ^ z)))
#define F1(x, y, z) (x ^ y ^ z)
#define F2(x, y, z) ((x & y) | (z & (x | y)))
#define F3(x, y, z) (x ^ y ^ z)

static void ccsha1_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *buf)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    uint32_t a, b, c, d, e, W[80], i;
#if CC_SMALL_CODE
    uint32_t t;
#endif

    while (nblocks--) {
        /* copy the state into 512-bits into W[0..15] */
        for (i = 0; i < 16; i++) {
            cc_load32_be(W[i], ptr + (4 * i));
        }

        /* copy state */
        a = ccdigest_u32(state)[0];
        b = ccdigest_u32(state)[1];
        c = ccdigest_u32(state)[2];
        d = ccdigest_u32(state)[3];
        e = ccdigest_u32(state)[4];

        /* expand it */
        for (i = 16; i < 80; i++) {
            W[i] = cc_rol(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
        }

/* compress */
/* round one */
#define FF0(a, b, c, d, e, i)                                    \
    e = (cc_rolc(a, 5) + F0(b, c, d) + e + W[i] + 0x5a827999UL); \
    b = cc_rolc(b, 30);
#define FF1(a, b, c, d, e, i)                                    \
    e = (cc_rolc(a, 5) + F1(b, c, d) + e + W[i] + 0x6ed9eba1UL); \
    b = cc_rolc(b, 30);
#define FF2(a, b, c, d, e, i)                                    \
    e = (cc_rolc(a, 5) + F2(b, c, d) + e + W[i] + 0x8f1bbcdcUL); \
    b = cc_rolc(b, 30);
#define FF3(a, b, c, d, e, i)                                    \
    e = (cc_rolc(a, 5) + F3(b, c, d) + e + W[i] + 0xca62c1d6UL); \
    b = cc_rolc(b, 30);

#if CC_SMALL_CODE

        for (i = 0; i < 20;) {
            FF0(a, b, c, d, e, i++);
            t = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = t;
        }

        for (; i < 40;) {
            FF1(a, b, c, d, e, i++);
            t = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = t;
        }

        for (; i < 60;) {
            FF2(a, b, c, d, e, i++);
            t = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = t;
        }

        for (; i < 80;) {
            FF3(a, b, c, d, e, i++);
            t = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = t;
        }

#else

        for (i = 0; i < 20;) {
            FF0(a, b, c, d, e, i++);
            FF0(e, a, b, c, d, i++);
            FF0(d, e, a, b, c, i++);
            FF0(c, d, e, a, b, i++);
            FF0(b, c, d, e, a, i++);
        }

        /* round two */
        for (; i < 40;) {
            FF1(a, b, c, d, e, i++);
            FF1(e, a, b, c, d, i++);
            FF1(d, e, a, b, c, i++);
            FF1(c, d, e, a, b, i++);
            FF1(b, c, d, e, a, i++);
        }

        /* round three */
        for (; i < 60;) {
            FF2(a, b, c, d, e, i++);
            FF2(e, a, b, c, d, i++);
            FF2(d, e, a, b, c, i++);
            FF2(c, d, e, a, b, i++);
            FF2(b, c, d, e, a, i++);
        }

        /* round four */
        for (; i < 80;) {
            FF3(a, b, c, d, e, i++);
            FF3(e, a, b, c, d, i++);
            FF3(d, e, a, b, c, i++);
            FF3(c, d, e, a, b, i++);
            FF3(b, c, d, e, a, i++);
        }
#endif

#undef FF0
#undef FF1
#undef FF2
#undef FF3

        /* store */
        ccdigest_u32(state)[0] += a;
        ccdigest_u32(state)[1] += b;
        ccdigest_u32(state)[2] += c;
        ccdigest_u32(state)[3] += d;
        ccdigest_u32(state)[4] += e;

        ptr += CCSHA1_BLOCK_SIZE;
    }
}

const struct ccdigest_info ccsha1_ltc_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid_size = ccoid_sha1_len,
    .oid = ccoid_sha1,
    .initial_state = &ccsha1_initial_state,
    .compress = &ccsha1_ltc_compress,
    .final = &ccdigest_final_64be,

    .digest_impl_name = "ccsha1 (ltc)",
};
