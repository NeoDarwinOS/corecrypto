/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_ctr_init(const struct ccmode_ctr *ctr, ccctr_ctx *ctx, size_t key_size, const void *key, const void *iv)
{
    cc_error_t err = CCERR_OK;
    const struct ccmode_ecb *ecb = (const struct ccmode_ecb *)ctr->custom;

    /* Now, this shouldn't be used by any SPI beyond ccmode_factory_xxx, but just in case... */
    cc_debug_abort(ecb == NULL, "ccmode_ctr_init: ecb field is null.", CCERR_PARAMETER);

    cc_debug_log("ctx ptr %p", ctx);
    cc_debug_log("key ptr %p", key);
    cc_debug_log("iv ptr %p", iv);

    CCMODE_CTR_KEY_ECB(ctx) = ecb;

    err = ccecb_init(ecb, CCMODE_CTR_KEY_ECB_CTX(ctx), key_size, key);
    if (err == CCERR_OK) {
        err = ccctr_setctr(ctr, ctx, iv);
    }

    return err;
}
