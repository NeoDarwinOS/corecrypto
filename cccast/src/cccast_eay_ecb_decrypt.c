/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cast.h"

CC_PRIVATE
cc_error_t cccast_eay_ecb_decrypt(const ccecb_ctx *ctx,
                                      size_t nblocks,
                                      const void *in,
                                      void *out)
{
    const CAST_KEY *key = (const CAST_KEY *)ctx;
    const uint8_t *ct = (const uint8_t *)in;
    uint8_t *pt = (uint8_t *)out;
    uint32_t work[2];

    while (nblocks--) {
        cc_load32_be(work[0], ct);
        cc_load32_be(work[1], ct+4);
        
        CAST_decrypt(work, key);

        /* store */
        cc_store32_be(work[0], pt);
        cc_store32_be(work[1], pt+4);
        
        pt += 8;
        ct += 8;
    }
    
    return CCERR_OK;
}

const struct ccmode_ecb cccast_eay_ecb_decrypt_mode = {
    .size = ccn_sizeof_size(sizeof(CAST_KEY)),
    .block_size = CCCAST_BLOCK_SIZE,
    .init = &cccast_setup,
    .ecb = &cccast_eay_ecb_decrypt,
    
    .impl_name = "EAY",
};
