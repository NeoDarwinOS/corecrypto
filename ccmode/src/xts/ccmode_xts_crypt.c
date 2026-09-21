/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccmode_internal.h>

void ccmode_xts_mult_alpha(uint8_t *I) {
    uint8_t t, tt = 0;

    for (size_t idx = t = 0; idx < 16; idx++) {
        tt = I[idx] >> 7;
        I[idx] = ((I[idx] << 1) | t) & 0xFF;
        t = tt;
    }

    if (tt) {
        I[0] ^= 0x87;
    }
}

void *ccmode_xts_crypt(const ccxts_ctx *ctx,
                       ccxts_tweak *tweak,
                       size_t nblocks,
                       const void *in,
                       void *out) {
    const uint8_t *_in = (const uint8_t *)in;
    uint8_t *_out = (uint8_t *)out;
    void *twk = NULL;
    
    while (nblocks--) {
        // This is a requirement established by NIST SP800-38E.
        twk = NULL;
        cc_require(CCMODE_XTS_TWEAK_BLOCKS_PROCESSED(tweak) < CCMODE_XTS_TWEAK_MAX_BLOCKS_PROCESSED, out);
        
        // in ^ twk
        cc_xor(CCMODE_XTS_KEY_ECB_ENCRYPT_MODE(ctx)->block_size, _out, _in, CCMODE_XTS_TWEAK_BUFFER(tweak));
        
        // crypt
        cc_require(ccecb_update(CCMODE_XTS_KEY_ECB_MODE(ctx), CCMODE_XTS_KEY_ECB_CTX(ctx), 1, _out, _out) == 0, out);
        
        // out ^ twk
        cc_xor(CCMODE_XTS_KEY_ECB_ENCRYPT_MODE(ctx)->block_size, _out, _out, CCMODE_XTS_TWEAK_BUFFER(tweak));
        
        // update twk
        ccmode_xts_mult_alpha((uint8_t *)CCMODE_XTS_TWEAK_BUFFER(tweak));
        CCMODE_XTS_TWEAK_BLOCKS_PROCESSED(tweak)++;
        
        _in += CCMODE_XTS_KEY_ECB_MODE(ctx)->block_size;
        _out += CCMODE_XTS_KEY_ECB_MODE(ctx)->block_size;
        
        // i actually dont know if this is correct
        twk = (void *)CCMODE_XTS_TWEAK_BUFFER(tweak);
    }
    
out:
    return twk;
}
