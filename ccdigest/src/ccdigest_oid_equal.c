/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>

bool ccdigest_oid_equal(const struct ccdigest_info *di, ccoid_t oid)
{
    if (di->oid == NULL && oid == NULL) {
        return true;
    } else if (di->oid == NULL || oid == NULL) {
        return false;
    } else {
        return ccoid_equal(di->oid, oid);
    }
}
