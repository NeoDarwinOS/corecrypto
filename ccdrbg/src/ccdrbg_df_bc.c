/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto/cc.h"
#include "corecrypto/ccmode.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg_df.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/ccn.h>

struct bcc_chain_ctx {
    struct ccmode_cbc *cbc_info;

};

#define MAX_DF_TEMP_SIZE    (CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE)
#define MAX_DF_BLOCK_SIZE   (CCAES_BLOCK_SIZE)

static cc_error_t
ccdrbg_df_bc_update_bcc_chain(const ccdrbg_df_bc_ctx_t *ctx,
                              const cccbc_ctx *cbc_ctx,
                              cccbc_iv *cbc_iv,
                              uint8_t *block,
                              size_t *bytes_processed,
                              const void *in, size_t nbytes)
{
    size_t block_size = cccbc_block_size(ctx->cbc);
    cc_error_t err = CCERR_OK;

    size_t want = (block_size - *bytes_processed);
    const uint8_t *_in = (const uint8_t *)in;

    if (*bytes_processed && nbytes >= want) {
        cc_copy(want, block+*bytes_processed, _in);
        err = cccbc_update(ctx->cbc, cbc_ctx, cbc_iv, 1, block, block);
        if (err) {
            return err;
        }
        nbytes -= want;
        _in += want;
        *bytes_processed = 0;
    }

    while (nbytes >= block_size) {
        cccbc_update(ctx->cbc, cbc_ctx, cbc_iv, 1, _in, block);
        nbytes -= block_size;
        _in += block_size;
    }

    if (nbytes > 0) {
        cc_copy(nbytes, block+*bytes_processed, _in);
        *bytes_processed += nbytes;
    }

    return err;
}

cc_error_t ccdrbg_df_bc_derive_keys(const ccdrbg_df_ctx_t *ctx,
                                 size_t nvec,
                                 const cc_iovec_t *iovecs,
                                 size_t key_nbytes,
                                 void *keys)
{
    const ccdrbg_df_bc_ctx_t *df_ctx = (const ccdrbg_df_bc_ctx_t *)ctx;
    cc_error_t err = CCERR_OK;
    size_t total_input_nbytes = 0;
    cccbc_ctx_decl(cccbc_context_size(df_ctx->cbc), cbc_ctx);
    cccbc_iv_decl(cccbc_block_size(df_ctx->cbc), cbc_iv);
    uint32_t prefix[6] = {0,0,0,0,0,0};
    const uint8_t suffix[MAX_DF_BLOCK_SIZE] = { 0x80 };
    size_t suffix_nbytes = 0;
    uint8_t temp[MAX_DF_TEMP_SIZE];
    size_t temp_nbytes_need = df_ctx->key_nbytes + cccbc_block_size(df_ctx->cbc);
    size_t temp_nbytes = 0;
    uint8_t block[MAX_DF_BLOCK_SIZE];
    uint8_t *kp = keys;
    void *x = temp + df_ctx->key_nbytes;
    size_t i = 0;

    prefix[5] = cc_h2be32((uint32_t)key_nbytes); 

    for (size_t v = 0; v < nvec; v++) {
        total_input_nbytes += iovecs[v].nbytes;
    }

    prefix[4] = cc_h2be32((uint32_t)total_input_nbytes);
    suffix_nbytes = cccbc_block_size(df_ctx->cbc) - ((sizeof(prefix) + total_input_nbytes) % cccbc_block_size(df_ctx->cbc));


    while (temp_nbytes < temp_nbytes_need) {
        cccbc_iv_clear(cccbc_block_size(df_ctx->cbc), cbc_iv);
        uint8_t *p = temp + temp_nbytes;
        size_t left = 0;
        prefix[0] = cc_h2be32((uint32_t)i);

        err = ccdrbg_df_bc_update_bcc_chain(df_ctx,
                     df_ctx->cbc_ctx,
                     cbc_iv,
                     p,
                     &left,
                     prefix,
                     sizeof(prefix));

        for (size_t j = 0; j < nvec; j++) {
            err = ccdrbg_df_bc_update_bcc_chain(df_ctx,
                     df_ctx->cbc_ctx,
                     cbc_iv,
                     p,
                     &left,
                     iovecs[j].base,
                     iovecs[j].nbytes);
        }

        err = ccdrbg_df_bc_update_bcc_chain(df_ctx,
                     df_ctx->cbc_ctx,
                     cbc_iv,
                     p,
                     &left,
                     suffix,
                     suffix_nbytes);

        i += 1;
        temp_nbytes += cccbc_block_size(df_ctx->cbc);
    }

    cccbc_init(df_ctx->cbc, cbc_ctx, df_ctx->key_nbytes, temp);
    while (key_nbytes > 0) {
        cccbc_iv_clear(cccbc_block_size(df_ctx->cbc), cbc_iv);

        uint8_t *p = (key_nbytes >= cccbc_block_size(df_ctx->cbc)) ? kp : block;
        err = cccbc_update(df_ctx->cbc, cbc_ctx, cbc_iv, 1, x, p);

        if (key_nbytes < cccbc_block_size(df_ctx->cbc)) {
            cc_memcpy(kp, p, key_nbytes);
        }

        x = p;
        kp += cc_min(key_nbytes, (size_t)cccbc_block_size(df_ctx->cbc));
        key_nbytes -= cc_min(key_nbytes, (size_t)cccbc_block_size(df_ctx->cbc));
    }

    cccbc_ctx_clear(df_ctx->cbc->size, cbc_ctx);
    cccbc_iv_clear(df_ctx->cbc->block_size, cbc_iv);

    return CCERR_OK;
}

cc_error_t ccdrbg_df_bc_init(ccdrbg_df_bc_ctx_t *ctx, const struct ccmode_cbc *cbc, size_t key_nbytes)
{
    cc_error_t err = CCERR_INTERNAL;

    static const uint8_t df_key[CCAES_KEY_SIZE_256] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    err = cccbc_init(cbc, ctx->cbc_ctx, key_nbytes, df_key);
    if (err != CCERR_OK) {
        return err;
    }

    ctx->cbc = cbc;
    ctx->derive_keys = &ccdrbg_df_bc_derive_keys;
    ctx->key_nbytes = key_nbytes;

    return CCERR_OK;
}
