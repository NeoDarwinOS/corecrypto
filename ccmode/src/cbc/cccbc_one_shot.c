/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode.h>

cc_error_t cccbc_one_shot(const struct ccmode_cbc *cbc, size_t key_length, const void *key, size_t nblocks, const void *iv, const void *in, void *out)
{
    cc_error_t err = CCERR_OK;

    cccbc_ctx_decl(cccbc_context_size(cbc), ctx);
    cccbc_iv_decl(cccbc_block_size(cbc), iv_ctx);
    err = cccbc_init(cbc, ctx, key_length, key);
    if (err == CCERR_OK) {
        err = cccbc_update(cbc, ctx, iv_ctx, nblocks, in, out);
    }

    cccbc_iv_clear(cccbc_block_size(cbc), iv_ctx);
    cccbc_ctx_clear(cccbc_context_size(cbc), ctx);
    return err;
}
