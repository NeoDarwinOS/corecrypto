/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode.h>

cc_error_t ccecb_init(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_size, const void *key)
{
    return ecb->init(ecb, ctx, key_size, key);
}
