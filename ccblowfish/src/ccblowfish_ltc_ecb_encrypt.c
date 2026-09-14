/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccblowfish_ltc_common.h"

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

cc_error_t ccblowfish_ltc_ecb_encrypt(const ccecb_ctx *ctx,
                                      size_t nblocks,
                                      const void *in,
                                      void *out)
{
    const ltc_blowfish_key *skey = (const ltc_blowfish_key *)ctx;
    const uint8_t *pt = (const uint8_t *)in;
    uint8_t *ct = (uint8_t *)out;
    uint32_t L, R;
    int r;
 #ifndef __GNUC__
    uint32_t *S1, *S2, *S3, *S4;
 #endif

 #ifndef __GNUC__
     S1 = skey->S[0];
     S2 = skey->S[1];
     S3 = skey->S[2];
     S4 = skey->S[3];
 #endif
    
    while (nblocks--) {
        cc_load32_be(L, &pt[0]);
        cc_load32_be(R, &pt[4]);
        
        /* do 16 rounds */
        for (r = 0; r < 16; ) {
            L ^= skey->K[r++];  R ^= F(L);
            R ^= skey->K[r++];  L ^= F(R);
            L ^= skey->K[r++];  R ^= F(L);
            R ^= skey->K[r++];  L ^= F(R);
        }

        /* last keying */
        R ^= skey->K[17];
        L ^= skey->K[16];

        /* store */
        cc_store32_be(R, &ct[0]);
        cc_store32_be(L, &ct[4]);
        
        pt += CCBLOWFISH_BLOCK_SIZE;
        ct += CCBLOWFISH_BLOCK_SIZE;
    }
    
    return CCERR_OK;
}

const struct ccmode_ecb ccblowfish_ltc_ecb_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(ltc_blowfish_key)),
    .block_size = CCBLOWFISH_BLOCK_SIZE,
    .init = &ccblowfish_ltc_setup,
    .ecb = &ccblowfish_ltc_ecb_encrypt,

    .impl_name = "ltc",
};
