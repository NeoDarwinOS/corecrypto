/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

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

#ifndef ltc_des_common_h
#define ltc_des_common_h

#include <corecrypto/ccdes.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

struct ltc_des_key {
    uint32_t ek[32], dk[32];
};

struct ltc_des3_key {
    uint32_t ek[3][32], dk[3][32];
};

CC_PRIVATE
void deskey(const unsigned char *key, short edf, uint32_t *keyout);
CC_PRIVATE
void desfunc(uint32_t *block, const uint32_t *keys);

CC_PRIVATE
int ltc_des3_setup(const unsigned char *key, size_t keylen, int num_rounds, ccecb_ctx *skey);
CC_PRIVATE
int ltc_des_setup(const unsigned char *key, size_t keylen, int num_rounds, ccecb_ctx *skey);

CC_PRIVATE
cc_error_t ccdes_ltc_setup(const struct ccmode_ecb *ecb,
                           ccecb_ctx *ctx,
                           size_t key_size,
                           const void *key);

CC_PRIVATE
cc_error_t ccdes3_ltc_setup(const struct ccmode_ecb *ecb,
                            ccecb_ctx *ctx,
                            size_t key_size,
                            const void *key);

#define EN0 0
#define DE1 1

#endif /* ltc_des_common_h */
