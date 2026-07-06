/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCSHA2_INTERNAL_H__
#define __CORECRYPTO_CCSHA2_INTERNAL_H__

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest_internal.h>
#include <corecrypto/ccsha2.h>

CC_BEGIN_DECLS

CC_PRIVATE
const uint32_t ccsha224_initial_state[8];

CC_PRIVATE
const uint32_t ccsha256_initial_state[8];

CC_PRIVATE
const uint64_t ccsha384_initial_state[8];

CC_PRIVATE
const uint64_t ccsha512_initial_state[8];

CC_PRIVATE
const uint64_t ccsha512_224_initial_state[8];

CC_PRIVATE
const uint64_t ccsha512_256_initial_state[8];

CC_PRIVATE
const uint32_t ccsha256_K[64];

CC_PRIVATE
const uint64_t ccsha512_K[80];

CC_PRIVATE
void ccsha256_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *in);

CC_PRIVATE
void ccsha512_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *in);

CC_PRIVATE
void ccsha512_final(const struct ccdigest_info *info, ccdigest_ctx_t ctx, void *digest);

CC_PRIVATE
void ccsha512_224_final(const struct ccdigest_info *info, ccdigest_ctx_t ctx, void *digest);


CC_END_DECLS

#endif /* __CORECRYPTO_CCSHA1_INTERNAL_H__ */
