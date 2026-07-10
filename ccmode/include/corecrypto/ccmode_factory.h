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

void ccmode_factory_cbc_decrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

void ccmode_factory_ctr_crypt(struct ccmode_ctr *cbc,
                              const struct ccmode_ecb *ecb);

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_FACTORY_H__ */
