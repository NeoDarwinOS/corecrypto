/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>

void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t length, const void *data)
{
    const uint8_t *ptr = (const uint8_t *)data;

    while (length) {
        if (ccdigest_num(di, ctx) == 0 && length > di->block_size) {
            size_t blocks = length / di->block_size;
            size_t bytes = blocks * di->block_size;

            di->compress(ccdigest_state(di, ctx), blocks, ptr);
            ccdigest_nbits(di, ctx) += (bytes << 3);

            length -= bytes;
            ptr += bytes;
        } else {
            /* If there's leftover data, accumulate it for later in case the update function is called again. */
            size_t leftover = (di->block_size - ccdigest_num(di, ctx));

            if (length < leftover) {
                leftover = length;
            }

            cc_copy(leftover, (ccdigest_data(di, ctx) + ccdigest_num(di, ctx)), data);
            length -= leftover;
            ptr += leftover;

            if (ccdigest_num(di, ctx) == di->block_size) {
                di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
                ccdigest_nbits(di, ctx) += (di->block_size << 3);
                ccdigest_num(di, ctx) = 0;
            }
        }
    }
}
