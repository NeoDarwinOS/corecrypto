/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccaes.h>
#include <corecrypto/cckprng.h>

#define CCKPRNG_PERSONALIZATION_STRING "cc_kprng"

void cckprng_init(struct cckprng_ctx *ctx, 
                  uint32_t ngens, 
                  size_t entropybuf_nbytes, 
                  const void *entropybuf, 
                  const uint32_t *entropybuf_nsamples, 
                  size_t seed_nbytes, 
                  const void *seed, 
                  size_t nonce_nbytes, 
                  const void *nonce)
{
    //
    // we first begin by initialising the lock
    //
    cc_lock_init(&ctx->lock, "corecrypto kprng");

    ctx->drbg_state = (struct ccdrbg_state *)&ctx->state[0];

    ccdrbg_df_bc_init(&ctx->df_ctx, ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_256);

    const struct ccdrbg_nistctr_custom custom = {
        ccaes_ctr_crypt_mode(),
        CCAES_KEY_SIZE_256,
        true,
        (ccdrbg_df_ctx_t *)&ctx->df_ctx,
    };

    ccdrbg_factory_nistctr(&ctx->drbg_info, &custom);

    ccdrbg_init(&ctx->drbg_info, 
                ctx->drbg_state, 
                seed_nbytes, seed, 
                nonce_nbytes, nonce, 
                sizeof(CCKPRNG_PERSONALIZATION_STRING)-1, CCKPRNG_PERSONALIZATION_STRING);

    //
    // i386:
    //  entropy buffer sample is *ebuffer = ror32(*ebuffer, 9) ^ tsc_lo
    //
    //  it might be beneficial to update our entropy system
    //
    ctx->entropybuf.buf = entropybuf;
    ctx->entropybuf.n_samples = entropybuf_nsamples;
    ctx->entropybuf.nbytes = entropybuf_nbytes;
}