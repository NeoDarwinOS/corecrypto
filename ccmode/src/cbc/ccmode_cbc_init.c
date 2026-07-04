/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_cbc_init(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, size_t rk_len, const void *rk)
{
    cc_error_t err = CCERR_OK;
    const struct ccmode_ecb *ecb = (const struct ccmode_ecb *)cbc->custom;

    /* Now, this shouldn't be used by any SPI beyond ccmode_factory_xxx, but just in case... */
    cc_debug_abort(ecb == NULL, "ccmode_cbc_init: ecb field is null.", CCERR_PARAMETER);

    CCMODE_CBC_KEY_ECB(ctx) = ecb;

    err = ccecb_init(ecb, CCMODE_CBC_KEY_ECB_CTX(ctx), rk_len, rk);

    return err;
}
