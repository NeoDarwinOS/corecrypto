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

cc_error_t ccmode_xts_key_sched(const struct ccmode_xts *xts,
                                ccxts_ctx *ctx,
                                size_t key_size,
                                const void *data_key,
                                const void *tweak_key) {
    cc_error_t err = CCERR_OK;
    
    // I... believe this is a requirement? Somewhere?
    int keys_same = cc_cmp_safe(key_size, data_key, tweak_key);
    cc_debug_client_abort(keys_same != 0, "ccmode_xts_key_sched: WTF? Keys are equal. API misuse.", CCERR_PARAMETER);

    // erase contexts after fail?
    err = ccecb_init(CCMODE_XTS_KEY_ECB_MODE(ctx), CCMODE_XTS_KEY_ECB_CTX(ctx), key_size, data_key);
    cc_require(err == CCERR_OK, out);
    err = ccecb_init(CCMODE_XTS_KEY_ECB_ENCRYPT_MODE(ctx), CCMODE_XTS_KEY_ECB_ENCRYPT_CTX(ctx), key_size, tweak_key);
    cc_require(err == CCERR_OK, out);
    
    out:
    return err;
}
