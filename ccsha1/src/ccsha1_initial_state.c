/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccsha1_internal.h>

const uint32_t ccsha1_initial_state[5] = {
    0x67452301U,
    0xefcdab89U,
    0x98badcfeU,
    0x10325476U,
    0xc3d2e1f0U,
};
