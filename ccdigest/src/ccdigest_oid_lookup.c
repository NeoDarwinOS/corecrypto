/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>

const struct ccdigest_info *ccdigest_oid_lookup(ccoid_t oid, ...)
{
    const struct ccdigest_info *di = NULL;
    va_list va;
    va_start(va, oid);

    while ((di = va_arg(va, const struct ccdigest_info *))) {
        if (ccdigest_oid_equal(di, oid)) {
            break;
        } else {
            di = NULL;
        }
    }

    return di;
}
