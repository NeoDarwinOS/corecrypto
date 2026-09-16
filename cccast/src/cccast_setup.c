/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "cast.h"

cc_error_t cccast_setup(const struct ccmode_ecb *ecb,
                        ccecb_ctx *ctx,
                        size_t key_nbytes,
                        const void *key)
{
    CAST_set_key((CAST_KEY *)ctx, key_nbytes, key);
    return CCERR_OK;
}
