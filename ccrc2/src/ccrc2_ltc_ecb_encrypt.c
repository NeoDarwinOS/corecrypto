/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccrc2_ltc_common.h"

/*
 * Code adapted from LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/**********************************************************************\
* To commemorate the 1996 RSA Data Security Conference, the following  *
* code is released into the public domain by its author.  Prost!       *
*                                                                      *
* This cipher uses 16-bit words and little-endian byte ordering.       *
* I wonder which processor it was optimized for?                       *
*                                                                      *
* Thanks to CodeView, SoftIce, and D86 for helping bring this code to  *
* the public.                                                          *
\**********************************************************************/

CC_PRIVATE
cc_error_t ltc_rc2_ecb_encrypt(const ccecb_ctx *ctx,
                               size_t nblocks,
                               const void *in,
                               void *out)
{
    uint32_t *xkey;
    xkey = ((ltc_rc2_key *)(ctx))->xkey;
    
    const uint8_t *pt = (const uint8_t *)in;
    uint8_t *ct = (uint8_t *)out;
    
    while (nblocks--) {
        uint32_t x76, x54, x32, x10;
        
        x76 = ((uint32_t)pt[7] << 8) + (uint32_t)pt[6];
        x54 = ((uint32_t)pt[5] << 8) + (uint32_t)pt[4];
        x32 = ((uint32_t)pt[3] << 8) + (uint32_t)pt[2];
        x10 = ((uint32_t)pt[1] << 8) + (uint32_t)pt[0];
        
        for (size_t i = 0; i < 16; i++) {
            x10 = (x10 + (x32 & ~x76) + (x54 & x76) + xkey[4*i+0]) & 0xFFFF;
            x10 = ((x10 << 1) | (x10 >> 15));
            
            x32 = (x32 + (x54 & ~x10) + (x76 & x10) + xkey[4*i+1]) & 0xFFFF;
            x32 = ((x32 << 2) | (x32 >> 14));
            
            x54 = (x54 + (x76 & ~x32) + (x10 & x32) + xkey[4*i+2]) & 0xFFFF;
            x54 = ((x54 << 3) | (x54 >> 13));
            
            x76 = (x76 + (x10 & ~x54) + (x32 & x54) + xkey[4*i+3]) & 0xFFFF;
            x76 = ((x76 << 5) | (x76 >> 11));
            
            if (i == 4 || i == 10) {
                x10 = (x10 + xkey[x76 & 63]) & 0xFFFF;
                x32 = (x32 + xkey[x10 & 63]) & 0xFFFF;
                x54 = (x54 + xkey[x32 & 63]) & 0xFFFF;
                x76 = (x76 + xkey[x54 & 63]) & 0xFFFF;
            }
        }
        
        ct[0] = (uint8_t)x10;
        ct[1] = (uint8_t)(x10 >> 8);
        ct[2] = (uint8_t)x32;
        ct[3] = (uint8_t)(x32 >> 8);
        ct[4] = (uint8_t)x54;
        ct[5] = (uint8_t)(x54 >> 8);
        ct[6] = (uint8_t)x76;
        ct[7] = (uint8_t)(x76 >> 8);
        
        pt += CCRC2_BLOCK_SIZE;
        ct += CCRC2_BLOCK_SIZE;
    }
    
    return CCERR_OK;
}

const struct ccmode_ecb ccrc2_ltc_ecb_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(ltc_rc2_key)),
    .block_size = CCRC2_BLOCK_SIZE,
    .init = &ccrc2_ltc_setup,
    .ecb = &ltc_rc2_ecb_encrypt,
    
    .impl_name = "LTC",
};

