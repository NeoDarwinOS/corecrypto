/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>

int cc_cmp_safe(size_t len, const void *p1, const void *p2)
{
    uint8_t flag = 0;
    const uint8_t *one = (const uint8_t *)p1;
    const uint8_t *two = (const uint8_t *)p2;

    if (len == 0) {
        return 1;
    }

    for (size_t i = len; i > 0; i--) {
        flag |= (one[i-1] ^ two[i-1]);
    }

    cc_heaviside_step(flag, flag);

    return flag;
}
