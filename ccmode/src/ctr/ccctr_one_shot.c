/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode.h>

cc_error_t ccctr_one_shot(const struct ccmode_ctr *ctr,
                          size_t key_length,
                          const void *key,
                          const void *iv,
                          size_t nbytes,
                          const void *in,
                          void *out)
{
    cc_error_t err = CCERR_OK;
    ccctr_ctx_decl(ctr->size, ctx);

    err = ccctr_init(ctr, ctx, key_length, key, iv);
    if (err == CCERR_OK) {
        err = ccctr_update(ctr, ctx, nbytes, in, out);
    }

    ccctr_ctx_clear(ctr->size, ctx);
    return err;
}
