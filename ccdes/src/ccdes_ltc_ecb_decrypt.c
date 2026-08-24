/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdes.h>
#include "ltc_des_common.h"

static cc_error_t ccdes_ltc_decrypt(const ccecb_ctx *ctx,
                                    size_t nblocks,
                                    const void *in,
                                    void *out)
{
    uint32_t work[2];
    const uint8_t *ct = (const uint8_t *)in;
    uint8_t *pt = (uint8_t *)out;
    const struct ltc_des_key *des = (const struct ltc_des_key *)ctx;
    
    while (nblocks--) {
        cc_load32_be(work[0], ct);
        cc_load32_be(work[1], ct+4);
        desfunc(work, des->dk);
        cc_store32_be(work[0], pt);
        cc_store32_be(work[1], pt+4);
        
        pt += CCDES_BLOCK_SIZE;
        ct += CCDES_BLOCK_SIZE;
    }
    
    return CCERR_OK;
}

//
// ccmode_ecb
//
const struct ccmode_ecb ccdes_ltc_ecb_decrypt_mode = {
    .size = ccn_sizeof_size(sizeof(struct ltc_des_key)),
    .block_size = CCDES_BLOCK_SIZE,
    
    .init = &ccdes_ltc_setup,
    .ecb = &ccdes_ltc_decrypt,
    
    .impl_name = "LTC"
};
