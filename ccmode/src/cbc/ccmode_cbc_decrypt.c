/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_cbc_decrypt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    cc_error_t err = CCERR_OK;
    const struct ccmode_ecb *ecb = CCMODE_CBC_KEY_ECB(ctx);
    size_t block_size = ccecb_block_size(ecb);
    uint8_t *_iv = (uint8_t *)iv;
    const uint8_t *_in = (const uint8_t *)in;
    uint8_t *_out = (uint8_t *)out;
    uint8_t buffer[CCMODE_MAX_BLOCK_SIZE];

    cc_debug_abort(CCMODE_MAX_BLOCK_SIZE < block_size, "ccmode_cbc_decrypt: block_size > CCMODE_MAX_BLOCK_SIZE", CCERR_PARAMETER);

    while (nblocks--) {
        err = ccecb_update(ecb, CCMODE_CBC_KEY_ECB_CTX(ctx), 1, _in, buffer);
        if (err == CCERR_OK) {
            for (cc_size i = 0; i < block_size; i++) {
                uint8_t t = _iv[i] ^ buffer[i];
                _iv[i] = _in[i];
                _out[i] = t;
            }

            _in += block_size;
            _out += block_size;
        } else {
            break;
        }
    }

    return err;
}
