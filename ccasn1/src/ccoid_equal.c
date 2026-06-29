/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccasn1.h>

bool ccoid_equal(ccoid_t oid1, ccoid_t oid2)
{
    if (ccoid_size(oid1) == ccoid_size(oid2)) {
        return (cc_cmp_safe(ccoid_size(oid1), oid1, oid2) == 0);
    }

    return false;
}
