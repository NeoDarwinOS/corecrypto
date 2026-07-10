/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/ccmode_internal.h>

cc_error_t ccmode_ctr_setctr(const struct ccmode_ctr *ctr, ccctr_ctx *ctx, const void *counter) {
    cc_debug_abort(counter == NULL, "ccmode_ctr_setctr: counter is null.", CCERR_PARAMETER);

    CCMODE_CTR_KEY_PAD_LENGTH(ctx) = CCMODE_CTR_KEY_ECB(ctx)->block_size;
    cc_copy(CCMODE_CTR_KEY_ECB(ctx)->block_size, CCMODE_CTR_KEY_COUNTER(ctx), counter);
    return CCERR_OK;
}
