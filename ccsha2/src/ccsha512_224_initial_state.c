/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccsha2_internal.h"

const uint64_t ccsha512_224_initial_state[8] = {
    0x8C3D37C819544DA2ULL,
    0x73E1996689DCD4D6ULL,
    0x1DFAB7AE32FF9C82ULL,
    0x679DD514582F9FCFULL,
    0x0F6D2B697BD44DA8ULL,
    0x77E36F7304C48942ULL,
    0x3F9D85A86A1D36C8ULL,
    0x1112E6AD91D692A1ULL,
};
