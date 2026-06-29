/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode.h>

cc_error_t cccbc_set_iv(const struct ccmode_cbc *mode, cccbc_iv *iv_ctx, const void *iv)
{
    if (iv) {
        cc_copy(cccbc_block_size(mode), iv_ctx, iv);
    } else {
        cc_clear(cccbc_block_size(mode), iv_ctx);
    }

    return CCERR_OK;
}
