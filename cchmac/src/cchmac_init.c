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
        cc_memcpy(cchmac_data(di, ctx), _key, key_length);
        
        /* Zero-fill the rest of the bytes */
        for (size_t i = di->block_size; i > key_length; i--) {
            cchmac_data(di, ctx)[i] = 0x00;
        }
    }
    
    /* After having done the above, we should be able to preconstruct parts of the opad state early. */
    for (size_t i = 0; i < di->block_size; i++) {
        cchmac_data(di, ctx)[i] ^= 0x5C;
    }
    
    /* Copy initial state to both istate and ostate */
    ccdigest_copy_state(di, cchmac_istate(di, ctx), di->initial_state);
    ccdigest_copy_state(di, cchmac_ostate(di, ctx), di->initial_state);
    
    /* Do opad first.  */
    di->compress(cchmac_ostate(di, ctx), 1, cchmac_data(di, ctx));
    
    for (size_t i = 0; i < di->block_size; i++) {
        cchmac_data(di, ctx)[i] ^= (0x5C ^ 0x36);
    }
    
    di->compress(cchmac_istate(di, ctx), 1, cchmac_data(di, ctx));
    
    /* This should prompt ccdigest_update into overwriting our data. */
    cchmac_num(di, ctx) = 0;
    cchmac_nbits(di, ctx) = (di->block_size << 3);
}
