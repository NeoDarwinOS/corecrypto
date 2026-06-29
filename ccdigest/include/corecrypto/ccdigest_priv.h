/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDIGEST_PRIV_H__
#define __CORECRYPTO_CCDIGEST_PRIV_H__

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest.h>

#define ccdigest_copy_state(_di_, _dst_, _src_) cc_memcpy_nochk(_dst_, _src_, (_di_)->state_size)

CC_EXPORT
bool ccdigest_oid_equal(const struct ccdigest_info *di,
                        ccoid_t oid);

CC_PRIVATE
const struct ccdigest_info *ccdigest_oid_lookup(ccoid_t oid, ...);

#endif /* __CORECRYPTO_CCDIGEST_PRIV_H__ */
