/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


#ifndef __CORECRYPTO_CCSS_SHAMIR_H__
#define __CORECRYPTO_CCSS_SHAMIR_H__

#include <corecrypto/cczp.h>

CC_BEGIN_DECLS

//
// CryptoKitPrivate re-exports a bunch of shamir secret sharing, but this didn't
// last forever in the OS... do we even need it?
//

struct ccss_shamir_generator {
    cczp_t field;
    uint32_t x;
    cc_unit y[];
};

CC_END_DECLS

#endif /* __CORECRYPTO_CCSS_SHAMIR_H__ */
