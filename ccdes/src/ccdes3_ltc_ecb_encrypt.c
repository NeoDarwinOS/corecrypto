/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdes.h>
#include "ltc_des_common.h"

static cc_error_t ccdes3_ltc_encrypt(const ccecb_ctx *ctx,
                                    size_t nblocks,
                                    const void *in,
                                    void *out)
{
    uint32_t work[2];
    const uint8_t *pt = (const uint8_t *)in;
    uint8_t *ct = (uint8_t *)out;
    const struct ltc_des3_key *des3 = (const struct ltc_des3_key *)ctx;
    
    while (nblocks--) {
        cc_load32_be(work[0], pt);
        cc_load32_be(work[1], pt+4);
        desfunc(work, des3->ek[0]);
        desfunc(work, des3->ek[1]);
        desfunc(work, des3->ek[2]);
        cc_store32_be(work[0], ct);
        cc_store32_be(work[1], ct+4);
        
        pt += CCDES_BLOCK_SIZE;
        ct += CCDES_BLOCK_SIZE;
    }
    
    return CCERR_OK;
}

//
// ccmode_ecb
//
const struct ccmode_ecb ccdes3_ltc_ecb_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(struct ltc_des3_key)),
    .block_size = CCDES_BLOCK_SIZE,
    
    .init = &ccdes3_ltc_setup,
    .ecb = &ccdes3_ltc_encrypt,
    
    .impl_name = "LTC"
};
