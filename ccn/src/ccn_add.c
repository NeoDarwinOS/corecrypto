/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccn.h>

/* ccn_add is supposed to return the carried bits. */
cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{

/* On 64-bit without double units, it gets hard. */
#if CC_UNIT_ALLOW_UINT128_DUNIT || (CC_UNIT_SIZE == 4)
    cc_dunit carry = 0;

    for (cc_size i = 0; i < n; i++) {
        carry = s[i] + t[i];

        r[i] = (cc_unit)carry;

        carry >>= CC_UNIT_BITS;
    }
#else
    #error ccn_add has been left without an impl
#endif

    return (cc_unit)carry;
}
