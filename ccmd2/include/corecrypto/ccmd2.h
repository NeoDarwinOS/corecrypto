/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMD2_H__
#define __CORECRYPTO_CCMD2_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

//
// According to CommonCrypto, some of these headers seem to define corresponding _di tokens not as functions,
// but macros.
//

#define CCMD2_BLOCK_SIZE   16
#define CCMD2_OUTPUT_SIZE  16
#define CCMD2_STATE_SIZE   64

#define ccoid_md2 CCOID("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02")
#define ccoid_md2_len 10

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
const struct ccdigest_info ccmd2_ltc_di;

#define ccmd2_di    ccmd2_ltc_di

CC_END_DECLS

#endif /* __CORECRYPTO_CCMD2_H__  */
