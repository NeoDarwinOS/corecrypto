/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "aes.h"
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccn.h>

cc_error_t ccaes_gladman_cbc_encrypt_init(const struct ccmode_cbc *cbc,
                                          cccbc_ctx *ctx,
                                          size_t key_size,
                                          const void *key)
{
    ccaes_gladman_encrypt_ctx *cx = (ccaes_gladman_encrypt_ctx *)ctx;

    if (key_size != CCAES_KEY_SIZE_128 &&
        key_size != CCAES_KEY_SIZE_192 &&
        key_size != CCAES_KEY_SIZE_256) {
        cc_debug_client_abort(1, "ccaes_gladman_cbc_encrypt_init: bad key length", CCERR_PARAMETER);
    } else {
        ccaes_gladman_encrypt_key(key, key_size, cx);
        cx->cbcEnable = 1;
        return CCERR_OK;
    }
}

cc_error_t ccaes_gladman_cbc_encrypt(const cccbc_ctx *ctx,
                                     cccbc_iv *iv,
                                     size_t nblocks,
                                     const void *in,
                                     void *out)
{
    return ccaes_gladman_encrypt(ctx, iv, nblocks, (const uint8_t *)in, (uint8_t *)out);
}

const struct ccmode_cbc ccaes_gladman_cbc_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(ccaes_gladman_encrypt_ctx)),
    .block_size = CCAES_BLOCK_SIZE,
    .init = &ccaes_gladman_cbc_encrypt_init,
    .cbc = &ccaes_gladman_cbc_encrypt,
    .custom = NULL,

    .impl_name = "gladman",
};
