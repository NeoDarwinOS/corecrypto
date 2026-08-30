/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMD4_H__
#define __CORECRYPTO_CCMD4_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

//
// According to CommonCrypto, some of these headers seem to define corresponding _di tokens not as functions,
// but macros.
//

#define CCMD4_BLOCK_SIZE   64
#define CCMD4_OUTPUT_SIZE  16
#define CCMD4_STATE_SIZE   16

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccdigest_info ccmd4_ltc_di;

#define ccmd4_di    ccmd4_ltc_di

CC_END_DECLS

#endif /* __CORECRYPTO_CCMD4_H__  */
