/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCCAST_H__
#define __CORECRYPTO_CCCAST_H__

#include <corecrypto/ccmode_impl.h>

CC_BEGIN_DECLS

#define CCCAST_BLOCK_SIZE 8

//
// Implementations
//
CC_EXPORT
const struct ccmode_ecb cccast_eay_ecb_decrypt_mode;

CC_EXPORT
const struct ccmode_ecb cccast_eay_ecb_encrypt_mode;

CC_EXPORT
const struct ccmode_ecb *cccast_ecb_encrypt_mode(void);

CC_EXPORT
const struct ccmode_ecb *cccast_ecb_decrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *cccast_cbc_encrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *cccast_cbc_decrypt_mode(void);

CC_EXPORT
const struct ccmode_ctr *cccast_ctr_crypt_mode(void);

CC_END_DECLS

#endif /* __CORECRYPTO_CCCAST_H__ */
