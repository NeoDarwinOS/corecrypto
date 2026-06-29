/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>

void ccdigest(const struct ccdigest_info *di, size_t length, const void *data, void *digest)
{
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    ccdigest_update(di, ctx, length, data);
    ccdigest_final(di, ctx, digest);
    ccdigest_di_clear(di, ctx);
}
