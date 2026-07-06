/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Code adapted from LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include "ccsha2_internal.h"

const uint32_t ccsha224_initial_state[8] = {
    0xc1059ed8U,
    0x367cd507U,
    0x3070dd17U,
    0xf70e5939U,
    0xffc00b31U,
    0x68581511U,
    0x64f98fa7U,
    0xbefa4fa4U,
};
