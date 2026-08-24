/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

/*
 * Baesd off of pseudocode from RFC 7539,
 *
 * see here:
 * https://datatracker.ietf.org/doc/html/rfc7539
 */

#define CHACHA_QROUND(state, a, b, c, d)        \
    state[a] += state[b];                       \
    state[d] = cc_rol(state[d] ^ state[a], 16); \
    state[c] += state[d];                       \
    state[b] = cc_rol(state[b] ^ state[c], 12); \
    state[a] += state[b];                       \
    state[d] = cc_rol(state[d] ^ state[a], 8);  \
    state[c] += state[d];                       \
    state[b] = cc_rol(state[b] ^ state[c], 7);


//
// Initialise the keystream
//
cc_error_t ccchacha20_init(ccchacha20_ctx *ctx, const void *key) {
    // msvc is very particular regarding void pointers.
    const uint8_t *_key = (const uint8_t *)key;
    
    // constants
    ctx->state[0] = cc_h2le32(0x61707865);
    ctx->state[1] = cc_h2le32(0x3320646e);
    ctx->state[2] = cc_h2le32(0x79622d32);
    ctx->state[3] = cc_h2le32(0x6b206574);
    
    // absorb key into state
    cc_load32_le(ctx->state[4], _key);
    cc_load32_le(ctx->state[5], _key+4);
    cc_load32_le(ctx->state[6], _key+8);
    cc_load32_le(ctx->state[7], _key+12);
    cc_load32_le(ctx->state[8], _key+16);
    cc_load32_le(ctx->state[9], _key+20);
    cc_load32_le(ctx->state[10], _key+24);
    cc_load32_le(ctx->state[11], _key+24);
    
    return CCERR_OK;
}

cc_error_t ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter) {
    ctx->state[12] = cc_h2le32(counter);
    return CCERR_OK;
}

cc_error_t ccchacha20_setnonce(ccchacha20_ctx *ctx, const void *nonce) {
    // msvc is very particular regarding void pointers.
    const uint8_t *_nonce = (const uint8_t *)nonce;
    
    cc_load32_le(ctx->state[13], _nonce);
    cc_load32_le(ctx->state[14], _nonce+4);
    cc_load32_le(ctx->state[15], _nonce+8);
    
    return CCERR_OK;
}

cc_error_t _ccchacha20_block(ccchacha20_ctx *ctx) {
    uint32_t *buffer = (uint32_t *)ctx->buffer;
    
    cc_copy(CCCHACHA20_BLOCK_NBYTES, ctx->buffer, ctx->state);
    
    for (int r = 20; r > 0; r -= 2) {
        CHACHA_QROUND(buffer, 0, 4, 8, 12);
        CHACHA_QROUND(buffer, 1, 5, 9, 13);
        CHACHA_QROUND(buffer, 2, 6, 10, 14);
        CHACHA_QROUND(buffer, 3, 7, 11, 15);
        CHACHA_QROUND(buffer, 0, 5, 10, 15);
        CHACHA_QROUND(buffer, 1, 6, 11, 12);
        CHACHA_QROUND(buffer, 2, 7, 8, 13);
        CHACHA_QROUND(buffer, 3, 4, 9, 14);
    }
    
    for (int s = 0; s < 16; s++) {
        buffer[s] += ctx->state[s];
    }
    
    return CCERR_OK;
}
