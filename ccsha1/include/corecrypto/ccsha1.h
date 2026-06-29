/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCSHA1_H__
#define __CORECRYPTO_CCSHA1_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

/*
 * SHA-1 algorithm, see FIPS 180 for more details.
 */
#define CCSHA1_BLOCK_SIZE   64
#define CCSHA1_OUTPUT_SIZE  20
#define CCSHA1_STATE_SIZE   20

CC_EXPORT
const struct ccdigest_info *ccsha1_di(void);

CC_EXPORT
const struct ccdigest_info ccsha1_ltc_di;

CC_EXPORT
const struct ccdigest_info ccsha1_eay_di;


/* OID constants */
#define ccoid_sha1 CCOID("\x06\x05\x2b\x0e\x03\x02\x1a")
#define ccoid_sha1_len 7

CC_END_DECLS

#endif /* __CORECRYPTO_CCSHA1_H__ */
