/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCAES_H__
#define __CORECRYPTO_CCAES_H__

#include <corecrypto/ccmode.h>

CC_BEGIN_DECLS

#define CCAES_BLOCK_SIZE    16

#define CCAES_KEY_SIZE_128  16
#define CCAES_KEY_SIZE_192  24
#define CCAES_KEY_SIZE_256  32

/*
 * Available implementations
 */
CC_EXPORT const struct ccmode_ecb ccaes_ltc_ecb_decrypt_mode;
CC_EXPORT const struct ccmode_ecb ccaes_ltc_ecb_encrypt_mode;

CC_EXPORT const struct ccmode_cbc ccaes_gladman_cbc_decrypt_mode;
CC_EXPORT const struct ccmode_cbc ccaes_gladman_cbc_encrypt_mode;

/*
 * Runtime selectors go here.
 */
CC_EXPORT
const struct ccmode_ecb *ccaes_ecb_decrypt_mode(void);

CC_EXPORT
const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *ccaes_cbc_decrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *ccaes_cbc_encrypt_mode(void);

CC_END_DECLS

#endif /* __CORECRYPTO_CCAES_H__  */
