/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_absolute_time.h>
#include <corecrypto/cckprng.h>

void cckprng_generate(struct cckprng_ctx *ctx, uint32_t gen_idx, size_t nbytes, void *out)
{
    //
    // TODO: We must keep being a cryptographic CSPRNG even in low-entropy environments.
    //
    //       There needs to be a shared implementation of CSPRNGs here, it would be beneficial and useful
    //       for any client of the library. Darwin 24 style. And also for ourselves to reduce code duplication.
    //
}
