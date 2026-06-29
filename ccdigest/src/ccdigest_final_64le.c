/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_internal.h>

void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    uint8_t *out = (uint8_t *)digest;

    /* increment the length of the message */
    ccdigest_nbits(di, ctx) += (ccdigest_num(di, ctx) << 3);
    ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x80;

    if (ccdigest_num(di, ctx) > 56) {
        while (ccdigest_num(di, ctx) < 64) {
            ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x00;
        }

        di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

        ccdigest_num(di, ctx) = 0;
    }

    while (ccdigest_num(di, ctx) < 56) {
        ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x00;
    }

    /* store the number of bits people */
    cc_store64_le(ccdigest_nbits(di, ctx), ccdigest_data(di, ctx));
    di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

    for (size_t i = 0; i < di->block_size / 4; i++) {
        cc_store32_le(ccdigest_state_u32(di, ctx)[i], out + (4 * i));
    }
}
