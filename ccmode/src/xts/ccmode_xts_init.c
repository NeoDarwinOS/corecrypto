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

cc_error_t ccmode_xts_init(const struct ccmode_xts *xts,
                           ccxts_ctx *ctx,
                           size_t key_size,
                           const void *data_key,
                           const void *tweak_key) {
    
    cc_error_t err = CCERR_OK;
    const struct ccmode_ecb *ecb = (const struct ccmode_ecb *)xts->custom;
    const struct ccmode_ecb *ecb_encrypt = (const struct ccmode_ecb *)xts->custom1;

    /* do we consider these cases corecrypto bugs or API abuse? */
    cc_debug_abort(ecb == NULL, "ccmode_xts_init: ecb field is null.", CCERR_PARAMETER);
    cc_debug_abort(ecb_encrypt == NULL, "ccmode_xts_init: ecb_encrypt field is null.", CCERR_PARAMETER);

    CCMODE_XTS_KEY_ECB_MODE(ctx) = ecb;
    CCMODE_XTS_KEY_ECB_ENCRYPT_MODE(ctx) = ecb_encrypt;
    
    err = ccmode_xts_key_sched(xts, ctx, key_size, data_key, tweak_key);

    return err;
}
