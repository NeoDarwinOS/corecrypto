/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cchmac.h>

void cchmac_init(const struct ccdigest_info *di,
                 cchmac_ctx_t ctx,
                 size_t key_length,
                 const void *key)
{
    const uint8_t *_key = (const uint8_t *)key;
    
    /* If the key is larger than the block size, we make it so by running the digest. */
    if (key_length > di->block_size) {
        ccdigest_init(di, cchmac_digest_ctx(di, ctx));
        ccdigest_update(di, cchmac_digest_ctx(di, ctx), key_length, key);
        ccdigest_final(di, cchmac_digest_ctx(di, ctx), cchmac_data(di, ctx));
    } else {
        
    }
}
