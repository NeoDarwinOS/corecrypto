/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cchmac.h>

void cchmac_update(const struct ccdigest_info *di,
                   cchmac_ctx_t ctx,
                   size_t data_length,
                   const void *data)
{
    ccdigest_update(di, cchmac_digest_ctx(di, ctx), data_length, data);
}
