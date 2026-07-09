/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMD5_H__
#define __CORECRYPTO_CCMD5_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

#define CCMD5_BLOCK_SIZE   64
#define CCMD5_OUTPUT_SIZE  16
#define CCMD5_STATE_SIZE   16

CC_EXPORT
const struct ccdigest_info *ccmd5_di(void);

CC_EXPORT
const struct ccdigest_info ccmd5_ltc_di;

CC_END_DECLS

#endif /* __CORECRYPTO_CCMD5_H__  */
