/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccsha2_internal.h"

void ccsha512_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    uint8_t *out = (uint8_t *)digest;

    /* increment the length of the message */
    ccdigest_nbits(di, ctx) += (ccdigest_num(di, ctx) << 3);
    ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x80;

    if (ccdigest_num(di, ctx) > 112) {
        while (ccdigest_num(di, ctx) < 128) {
            ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x00;
        }

        di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

        ccdigest_num(di, ctx) = 0;
    }

    while (ccdigest_num(di, ctx) < 120) {
        ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x00;
    }

    /* store the number of bits people */
    cc_store64_be(ccdigest_nbits(di, ctx), ccdigest_data(di, ctx));
    di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

    for (size_t i = 0; i < di->block_size / 8; i++) {
        cc_store64_be(ccdigest_state_u64(di, ctx)[i], out + (8 * i));
    }
}

/* Same underlying logic, however 28 is not divisible by four, so it will only copy out 24 bytes. */
void ccsha512_224_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    uint8_t *out = (uint8_t *)digest;

    /* increment the length of the message */
    ccdigest_nbits(di, ctx) += (ccdigest_num(di, ctx) << 3);
    ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x80;

    if (ccdigest_num(di, ctx) > 112) {
        while (ccdigest_num(di, ctx) < 128) {
            ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x00;
        }

        di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

        ccdigest_num(di, ctx) = 0;
    }

    while (ccdigest_num(di, ctx) < 120) {
        ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x00;
    }

    /* store the number of bits people */
    cc_store64_be(ccdigest_nbits(di, ctx), ccdigest_data(di, ctx));
    di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

    for (size_t i = 0; i < di->block_size / 8; i++) {
        cc_store64_be(ccdigest_state_u64(di, ctx)[i], out + (8 * i));
    }

    cc_store32_be(ccdigest_state_u32(di, ctx)[6], (out + 24));
}
