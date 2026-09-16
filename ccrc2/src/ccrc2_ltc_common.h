/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef ccrc2_ltc_common_h
#define ccrc2_ltc_common_h

#include <corecrypto/ccrc2.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_debug.h>

typedef struct ltc_rc2_key {
    uint32_t xkey[64];
} ltc_rc2_key;

cc_error_t ccrc2_ltc_setup(const struct ccmode_ecb *ecb,
                           ccecb_ctx *ctx,
                           size_t keylen,
                           const void *key);

#endif /* ccrc2_ltc_common_h */
