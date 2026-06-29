/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>

void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx)
{
    ccdigest_copy_state(di, ccdigest_state(di, ctx), di->initial_state);
    ccdigest_nbits(di, ctx) = 0;
    ccdigest_num(di, ctx) = 0;
}
