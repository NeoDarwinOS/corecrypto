/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdes.h>
#include "ltc_des_common.h"

cc_error_t ccdes_ltc_setup(const struct ccmode_ecb *ecb,
                           ccecb_ctx *ctx,
                           size_t key_size,
                           const void *key)
{
    return ltc_des_setup(key, (int)key_size, 0, ctx);
}
