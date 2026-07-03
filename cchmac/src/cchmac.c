/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cchmac.h>

void cchmac(const struct ccdigest_info *di,
            size_t key_length,
            const void *key,
            size_t data_length,
            const void *data,
            void *mac)
{
    cchmac_di_decl(di, ctx);
    cchmac_init(di, ctx, key_length, key);
    cchmac_update(di, ctx, data_length, data);
    cchmac_final(di, ctx, mac);
    cchmac_di_clear(di, ctx);
}
