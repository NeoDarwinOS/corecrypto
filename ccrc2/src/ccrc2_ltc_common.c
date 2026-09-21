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

static const uint8_t permute[256] = {
        217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
        198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
         23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
        189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
         84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
         18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
        111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
        248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
          8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
        150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
        194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
        153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
         45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
        211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
         13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
        197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
};

cc_error_t ccrc2_ltc_setup(const struct ccmode_ecb *ecb,
                           ccecb_ctx *ctx,
                           size_t keylen,
                           const void *key)
{
    ltc_rc2_key *skey = (ltc_rc2_key *)ctx;
    uint32_t *xkey = skey->xkey;
    uint8_t tmp[129] = {0};
    uint32_t T8, TM;
    size_t bits;
    
    for (size_t i = 0; i < keylen; i++) {
        tmp[i] = ((const uint8_t *)(key))[i] & 255;
    }
    
    /* Phase 1: Expand input key to 128 bytes */
    if (keylen < 128) {
        for (size_t i = keylen, j = 0; i < 128; i++, j++) {
            tmp[i] = permute[((tmp[i - 1]) + (tmp[j])) & 255];
        }
    }
    
    bits = keylen<<3;
    T8   = (uint32_t)(bits+7)>>3;
    TM   = (255 >> (uint32_t)(7 & -bits));
    tmp[128 - T8] = permute[(tmp[128 - T8]) & TM];

    for (size_t i = 127 - T8; i >= 0; i--) {
        tmp[i] = permute[(tmp[i + 1]) ^ (tmp[i + T8])];
    }

    /* Phase 3 - copy to xkey in little-endian order */
    for (size_t i = 0; i < 64; i++) {
        xkey[i] =  (uint32_t)tmp[2*i] + ((uint32_t)tmp[2*i+1] << 8);
    }
    
    return CCERR_OK;
}
