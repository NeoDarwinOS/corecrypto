/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>

void cc_xor(size_t len, void *r, const void *s, const void *t)
{
    uint8_t *rptr = (uint8_t *)r;
    const uint8_t *sptr = (const uint8_t *)s;
    const uint8_t *tptr = (const uint8_t *)t;
    while (len--) {
        rptr[len] = sptr[len] ^ tptr[len];
    }
}
