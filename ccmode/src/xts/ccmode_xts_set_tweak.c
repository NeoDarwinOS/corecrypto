/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_xts_set_tweak(const ccxts_ctx *ctx,
                                ccxts_tweak *tweak,
                                const void *iv) {
    
    // HOPEFULLY this IV is fresh.
    CCMODE_XTS_TWEAK_BLOCKS_PROCESSED(tweak) = 0;

    return ccecb_update(CCMODE_XTS_KEY_ECB_ENCRYPT_MODE(ctx),
                        CCMODE_XTS_KEY_ECB_ENCRYPT_CTX(ctx),
                        1,
                        iv,
                        CCMODE_XTS_TWEAK_BUFFER(tweak));
}

