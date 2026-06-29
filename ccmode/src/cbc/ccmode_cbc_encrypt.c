/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_cbc_encrypt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    cc_error_t err = CCERR_OK;
    const struct ccmode_ecb *ecb = CCMODE_CBC_KEY_ECB(ctx);
    size_t block_size = ccecb_block_size(ecb);
    uint8_t *_iv = (uint8_t *)iv;
    const uint8_t *_in = (const uint8_t *)in;
    uint8_t *_out = (uint8_t *)out;

    while (nblocks--) {
        cc_xor(block_size, _out, _in, _iv);
        err = ccecb_update(ecb, CCMODE_CBC_KEY_ECB_CTX(ctx), 1, _out, _out);

        if (err == CCERR_OK) {
            _iv = _out;
            _out += block_size;
            _in += block_size;
        } else {
            break;
        }
    }

    /* update the iv */
    cc_copy(block_size, iv, _out);

    return err;
}
