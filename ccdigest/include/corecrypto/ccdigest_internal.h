/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDIGEST_INTERNAL_H__
#define __CORECRYPTO_CCDIGEST_INTERNAL_H__

#include <corecrypto/ccdigest_priv.h>

/*
 * These are common functions shared amongst Message-Digest style padded hash functions.
 */

/* For the SHA-1 and SHA-2 family of functions. */
CC_PRIVATE
void ccdigest_final_64be(const struct ccdigest_info *info, ccdigest_ctx_t ctx, void *digest);

/* For RMD, MD4 and MD5, MD2 is special and has it's own final function. */
CC_PRIVATE
void ccdigest_final_64le(const struct ccdigest_info *info, ccdigest_ctx_t ctx, void *digest);

#endif /* __CORECRYPTO_CCDIGEST_INTERNAL_H__ */
