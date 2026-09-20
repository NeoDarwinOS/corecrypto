/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_FACTORY_H__
#define __CORECRYPTO_CCMODE_FACTORY_H__

#include <corecrypto/ccmode_impl.h>

CC_BEGIN_DECLS

/*!
 * @function ccmode_factory_cbc_decrypt
 * Initialises a ccmode_cbc structure using an ECB implementation, in the decryption mode.
 *
 * @param       cbc
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 *
 * @result      CBC structure is filled out.
 */
void ccmode_factory_cbc_decrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

/*!
 * @function ccmode_factory_cbc_encrypt
 * Initialises a ccmode_cbc structure using an ECB implementation, in the encryption mode.
 *
 * @param       cbc
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 *
 * @result      CBC structure is filled out.
 */
void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

/*!
 * @function ccmode_factory_ctr_crypt
 * Initialises a ccmode_ctr structure using an ECB implementation.
 *
 * @param       cbc
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 *
 * @result      CTR structure is filled out.
 */
void ccmode_factory_ctr_crypt(struct ccmode_ctr *cbc,
                              const struct ccmode_ecb *ecb);

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_FACTORY_H__ */
