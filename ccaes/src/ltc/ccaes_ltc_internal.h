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

#ifndef __CORECRYPTO_CCAES_LTC_INTERNAL_H__
#define __CORECRYPTO_CCAES_LTC_INTERNAL_H__

#include "ccaes_ltc_tab.h"
#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccn.h>

typedef struct ltc_rijndael_key {
  uint32_t eK[60], dK[60];
  int Nr;
} ltc_rijndael_keysched;

CC_PRIVATE
cc_error_t ccaes_ecb_decrypt_init(const struct ccmode_ecb *ecb, ccecb_ctx *ctx,
                                  size_t key_size, const void *key);

CC_PRIVATE
cc_error_t ccaes_ecb_encrypt_init(const struct ccmode_ecb *ecb, ccecb_ctx *ctx,
                                  size_t key_size, const void *key);

#endif /* __CORECRYPTO_CCAES_LTC_INTERNAL_H__ */
