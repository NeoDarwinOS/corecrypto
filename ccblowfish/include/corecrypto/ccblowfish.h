/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCBLOWFISH_H__
#define __CORECRYPTO_CCBLOWFISH_H__

#include <corecrypto/ccmode_impl.h>

CC_BEGIN_DECLS

//
// Blowfish used to be used for IPsec ESP. I doubt anyone uses it anymore, but CommonCrypto would like it.
//

#define CCBLOWFISH_BLOCK_SIZE   8
#define CCBLOWFISH_MIN_KEY_SIZE 8
#define CCBLOWFISH_MAX_KEY_SIZE 56

//
// Implementations
//
CC_EXPORT
const struct ccmode_ecb ccblowfish_ltc_ecb_decrypt_mode;

CC_EXPORT
const struct ccmode_ecb ccblowfish_ltc_ecb_encrypt_mode;

CC_EXPORT
const struct ccmode_ecb *ccblowfish_ecb_encrypt_mode(void);

CC_EXPORT
const struct ccmode_ecb *ccblowfish_ecb_decrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *ccblowfish_cbc_encrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *ccblowfish_cbc_decrypt_mode(void);

CC_EXPORT
const struct ccmode_ctr *ccblowfish_ctr_crypt_mode(void);

CC_END_DECLS

#endif /* __CORECRYPTO_CCBLOWFISH_H__ */
