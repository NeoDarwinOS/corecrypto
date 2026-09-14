/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef ccblowfish_ltc_h
#define ccblowfish_ltc_h

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

#include <corecrypto/ccblowfish.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_priv.h>

typedef struct ltc_blowfish_key {
   uint32_t S[4][256];
   uint32_t K[18];
} ltc_blowfish_key;

#ifndef __GNUC__
#define F(x) ((S1[cc_byte(x,3)] + S2[cc_byte(x,2)]) ^ S3[cc_byte(x,1)]) + S4[cc_byte(x,0)]
#else
#define F(x) ((skey->S[0][cc_byte(x,3)] + skey->S[1][cc_byte(x,2)]) ^ skey->S[2][cc_byte(x,1)]) + skey->S[3][cc_byte(x,0)]
#endif


CC_PRIVATE
cc_error_t ccblowfish_ltc_setup(const struct ccmode_ecb *ecb,
                                ccecb_ctx *ctx,
                                size_t key_nbytes,
                                const void *key);

CC_PRIVATE
cc_error_t ccblowfish_ltc_ecb_encrypt(const ccecb_ctx *ctx,
                                      size_t nblocks,
                                      const void *in, void *out);

#endif /* ccblowfish_ltc_h */
