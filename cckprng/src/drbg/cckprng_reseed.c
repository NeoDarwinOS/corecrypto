/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_absolute_time.h>
#include <corecrypto/cckprng.h>

//
// prior to being fed to us, xnu conditions the /dev/random write using sha-256 on Darwin 19
//
// worthy of note that we just feed ourself our own cryptographic data.
//
// ourboros of uh, entropy, i guess.
//
// prng_seedctl coming... eventually. i need to write it.
//
// modern darwin, aka: tahoe, feeds it without conditioning unless the seed is larger than 16 bytes, in
// which case, it runs SHA-512
//
void cckprng_reseed(struct cckprng_ctx *ctx, size_t nbytes, const void *seed)
{
    //
    // even with this seed being 16 bytes on tahoe, likely random from the host, 
    // we still need to incorporate a miniscule amount of EXTRA entropy to prevent prediction.
    //
    uint64_t now = cc_absolute_time();

    ccdrbg_reseed(&ctx->drbg_info, ctx->drbg_state, nbytes, seed, sizeof(now), &now);
}