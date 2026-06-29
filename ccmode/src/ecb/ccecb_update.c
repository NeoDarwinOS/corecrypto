/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccmode.h>

cc_error_t ccecb_update(const struct ccmode_ecb *ecb, const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    return ecb->ecb(ctx, nblocks, in, out);
}
