/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccsha2_internal.h"

const struct ccdigest_info ccsha512_224_ltc_di = {
    .output_size = CCSHA512_224_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha512_224_len,
    .oid = ccoid_sha512_224,
    .initial_state = &ccsha512_224_initial_state,
    .compress = &ccsha512_ltc_compress,
    .final = &ccsha512_224_final,

    .digest_impl_name = "LTC",
};
