/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDES_H__
#define __CORECRYPTO_CCDES_H__

#include <corecrypto/ccmode.h>

CC_BEGIN_DECLS

#define CCDES_BLOCK_SIZE    8

#define CCDES_KEY_SIZE      8

/*
 * Available implementations
 */
CC_EXPORT const struct ccmode_ecb ccdes_ltc_ecb_decrypt_mode;
CC_EXPORT const struct ccmode_ecb ccdes_ltc_ecb_encrypt_mode;

/*
 * Runtime selectors go here.
 */
CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_ecb *ccdes_ecb_decrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_ecb *ccdes_ecb_encrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_cbc *ccdes_cbc_decrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_cbc *ccdes_cbc_encrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_ctr *ccdes_ctr_crypt_mode(void);

#pragma mark - Triple DES

/*
 * Available implementations
 */
CC_EXPORT const struct ccmode_ecb ccdes3_ltc_ecb_decrypt_mode;
CC_EXPORT const struct ccmode_ecb ccdes3_ltc_ecb_encrypt_mode;

/*
 * Runtime selectors go here.
 */
CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_ecb *ccdes3_ecb_decrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_ecb *ccdes3_ecb_encrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_cbc *ccdes3_cbc_decrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_cbc *ccdes3_cbc_encrypt_mode(void);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccmode_ctr *ccdes3_ctr_crypt_mode(void);

#pragma mark - Utility functions

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
bool ccdes_key_is_weak(void *key, size_t length);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
void ccdes_key_set_odd_parity(void *key, size_t length);

CC_EXPORT
uint32_t ccdes_cbc_cksum(const void *in,
                         void *out,
                         size_t length,
                         const void *key,
                         size_t key_length,
                         const void *iv);


CC_END_DECLS

#endif /* __CORECRYPTO_CCDES_H__  */

