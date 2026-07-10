/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_ctr_crypt(ccctr_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    size_t block_size = CCMODE_CTR_KEY_ECB(ctx)->block_size;
    const uint8_t *_in = in;
    uint8_t *_out = out;
    uint8_t *_counter = CCMODE_CTR_KEY_COUNTER(ctx);
    uint8_t *_pad = CCMODE_CTR_KEY_PAD(ctx);
    size_t ctr_size = cc_min(block_size, 8);

    while (nbytes--) {
        if (CCMODE_CTR_KEY_PAD_LENGTH(ctx) == block_size) {
            ccecb_update(CCMODE_CTR_KEY_ECB(ctx), CCMODE_CTR_KEY_ECB_CTX(ctx), 1, CCMODE_CTR_KEY_COUNTER(ctx), _pad);
            CCMODE_CTR_KEY_PAD_LENGTH(ctx) = 0;

            inc_uint_be((CCMODE_CTR_KEY_COUNTER(ctx) + (block_size - ctr_size)), ctr_size);
        }

        *_out++ = *_in++ ^ _pad[CCMODE_CTR_KEY_PAD_LENGTH(ctx)++];
    }

    return CCERR_OK;
}
