/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCRC2_H__
#define __CORECRYPTO_CCRC2_H__

#include <corecrypto/ccmode_impl.h>

CC_BEGIN_DECLS

#define CCRC2_BLOCK_SIZE   8
#define CCRC2_MIN_KEY_SIZE 8
#define CCRC2_MAX_KEY_SIZE 128

//
// Implementations
//
CC_EXPORT
const struct ccmode_ecb ccrc2_ltc_ecb_decrypt_mode;

CC_EXPORT
const struct ccmode_ecb ccrc2_ltc_ecb_encrypt_mode;

CC_EXPORT
const struct ccmode_ecb *ccrc2_ecb_encrypt_mode(void);

CC_EXPORT
const struct ccmode_ecb *ccrc2_ecb_decrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *ccrc2_cbc_encrypt_mode(void);

CC_EXPORT
const struct ccmode_cbc *ccrc2_cbc_decrypt_mode(void);

CC_EXPORT
const struct ccmode_ctr *ccrc2_ctr_crypt_mode(void);

CC_END_DECLS

#endif /* __CORECRYPTO_CCRC2_H__ */
