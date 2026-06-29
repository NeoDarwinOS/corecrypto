/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode.h>

cc_error_t ccecb_one_shot(const struct ccmode_ecb *ecb,
                          size_t key_length,
                          const void *key,
                          size_t nblocks,
                          const void *in,
                          void *out)
{
    cc_error_t err;
    ccecb_ctx_decl(ecb->size, ctx);
    err = ccecb_init(ecb, ctx, key_length, key);
    if (err == CCERR_OK) {
        err = ccecb_update(ecb, ctx, nblocks, in, out);
    }

    ccecb_ctx_clear(ecb->size, ctx);
    return err;
}
