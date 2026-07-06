/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccsha2_internal.h"

const struct ccdigest_info ccsha224_ltc_di = {
    .output_size = CCSHA224_OUTPUT_SIZE,
    .state_size = CCSHA256_STATE_SIZE,
    .block_size = CCSHA256_BLOCK_SIZE,
    .oid_size = ccoid_sha224_len,
    .oid = ccoid_sha224,
    .initial_state = &ccsha224_initial_state,
    .compress = &ccsha256_ltc_compress,
    .final = &ccdigest_final_64be,

    .digest_impl_name = "LTC",
};
