/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

//-------------------------------------------
// Adapted from poly1305-donna, seen here: https://github.com/floodyberry/poly1305-donna
//-------------------------------------------

cc_error_t ccpoly1305_init(ccpoly1305_ctx *ctx,
                           const void *key) {
    uint32_t k[5] = {0};
    const uint8_t *_key = (const uint8_t *)key;
    
    cc_load32_le(k[0], _key);
    cc_load32_le(k[1], _key+4);
    cc_load32_le(k[2], _key+7);
    cc_load32_le(k[3], _key+10);
    cc_load32_le(k[3], _key+12);
    
    k[1] >>= 2;
    k[2] >>= 4;
    k[3] >>= 6;
    k[4] >>= 8;

    k[0] &= 0x3ffffff;
    k[1] &= 0x3ffff03;
    k[2] &= 0x3ffc0ff;
    k[3] &= 0x3f03fff;
    k[4] &= 0x00fffff;

    /* migrate these to ctx */
    ctx->r0 = k[0];
    ctx->r1 = k[1];
    ctx->r2 = k[2];
    ctx->r3 = k[3];
    ctx->r4 = k[4];

    /* do this now instead of later */
    ctx->s1 = ctx->r1 * 5;
    ctx->s2 = ctx->r2 * 5;
    ctx->s3 = ctx->r3 * 5;
    ctx->s4 = ctx->r4 * 5;

    cc_memcpy(ctx->key, key + 16, 16);
    
    return CCERR_OK;
}

static void _ccpoly1305_update(ccpoly1305_ctx *ctx,
                               size_t nbytes,
                               const void *in,
                               bool final) {
    uint32_t h0, h1, h2, h3, h4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c;
    uint64_t d0, d1, d2, d3, d4;

    r0 = ctx->r0;
    r1 = ctx->r1;
    r2 = ctx->r2;
    r3 = ctx->r3;
    r4 = ctx->r4;

    s1 = ctx->s1;
    s2 = ctx->s2;
    s3 = ctx->s3;
    s4 = ctx->s4;

    h0 = ctx->h0;
    h1 = ctx->h1;
    h2 = ctx->h2;
    h3 = ctx->h3;
    h4 = ctx->h4;

    while (nbytes >= 16) {
        h0 += (cc_read32_le(in + 0)) & 0x3ffffff;
        h1 += (cc_read32_le(in + 3) >> 2) & 0x3ffffff;
        h2 += (cc_read32_le(in + 6) >> 4) & 0x3ffffff;
        h3 += (cc_read32_le(in + 9) >> 6) & 0x3ffffff;
        h4 += (cc_read32_le(in + 12) >> 8) | (final ? 0 : (1 << 24));

        /* h *= r */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* (partial) h %= p */
        c = (uint32_t)(d0 >> 26);
        h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;
        c = (uint32_t)(d1 >> 26);
        h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;
        c = (uint32_t)(d2 >> 26);
        h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;
        c = (uint32_t)(d3 >> 26);
        h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;
        c = (uint32_t)(d4 >> 26);
        h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;
        c = (h0 >> 26);
        h0 = h0 & 0x3ffffff;
        h1 += c;

        in += 16;
        nbytes -= 16;
    }

    ctx->h0 = h0;
    ctx->h1 = h1;
    ctx->h2 = h2;
    ctx->h3 = h3;
    ctx->h4 = h4;
}

cc_error_t ccpoly1305_update(ccpoly1305_ctx *ctx,
                             size_t nbytes,
                             const void *in) {
    const uint8_t *p = in;

    if (ctx->buf_used) {
        /* copy the newest bytes into the buffer & run update */
        size_t bytes = 16 - ctx->buf_used;

        for (size_t i = bytes; i < 16; i++) {
            ctx->buf[i] = p[i];
        }

        _ccpoly1305_update(ctx, 16, ctx->buf, false);

        nbytes -= bytes;
        p += bytes;
    }

    if (nbytes >= 16) {
        size_t bytes = cc_ceiling(nbytes, 16) * 16;
        _ccpoly1305_update(ctx, bytes, in, false);
        nbytes -= bytes;
        p += bytes;
    }

    /* copy it into the buffer */
    if (nbytes) {
        for (size_t i = 0; i < nbytes; i++) {
            ctx->buf[i] = p[i];
        }

        ctx->buf_used = nbytes;
    }

    return CCERR_OK;
};

cc_error_t ccpoly1305_final(ccpoly1305_ctx *ctx,
                            void *tag) {
    uint32_t h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, c, mask;
    uint64_t f;

    if (ctx->buf_used) {
        size_t i = ctx->buf_used;
        ctx->buf[i++] = 1;
        for (; i < 16; i++) {
            ctx->buf[i] = 0;
        }

        _ccpoly1305_update(ctx, 16, ctx->buf, true);
    }

    h0 = ctx->h0;
    h1 = ctx->h1;
    h2 = ctx->h2;
    h3 = ctx->h3;
    h4 = ctx->h4;

    c = h1 >> 26;
    h1 = h1 & 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 = h2 & 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 = h3 & 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 = h4 & 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 = h0 & 0x3ffffff;
    h1 += c;

    /* compute h + -p */
    g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (uint64_t)h0 + ctx->key[0];
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->key[1] + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->key[2] + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->key[3] + (f >> 32);
    h3 = (uint32_t)f;

    cc_write32_le(tag, h0);
    cc_write32_le(tag + 4, h1);
    cc_write32_le(tag + 8, h2);
    cc_write32_le(tag + 12, h3);

    ctx->h0 = 0;
    ctx->h1 = 0;
    ctx->h2 = 0;
    ctx->h3 = 0;
    ctx->h4 = 0;

    return CCERR_OK;
}

cc_error_t ccpoly1305(const void *key,
                      size_t nbytes,
                      const void *in,
                      void *tag) {
    ccpoly1305_ctx ctx;
    cc_clear(sizeof(ccpoly1305_ctx), &ctx);
    cc_error_t ret = ccpoly1305_init(&ctx, key);
    ret = ccpoly1305_update(&ctx, nbytes, in);
    ret = ccpoly1305_final(&ctx, tag);
    cc_clear(sizeof(ccpoly1305_ctx), &ctx);
    return ret;
}
