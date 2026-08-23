/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDRBG_DF_H__
#define __CORECRYPTO_CCDRBG_DF_H__

#include <corecrypto/cc.h>
#include <corecrypto/ccmode.h>

CC_BEGIN_DECLS

/*
 * API NOTES:
 *
 * This is actually a Darwin 24 API surface.
 */

typedef struct ccdrbg_df_ctx ccdrbg_df_ctx_t;

#define CCDRBG_DF_COMMON                                        \
    cc_error_t (*derive_keys)(const ccdrbg_df_ctx_t *ctx,       \
                              size_t nvec,                      \
                              const cc_iovec_t *iovecs,         \
                              size_t key_nbytes,                \
                              void *keys)

struct ccdrbg_df_ctx {
    CCDRBG_DF_COMMON;
};

typedef struct ccdrbg_df_bc_ctx ccdrbg_df_bc_ctx_t;

/*
 * MAINTAINER'S NOTE:
 * This needs to be updated for every CBC implementation we use here.
 *
 * This is rough estimation based on the size of ccaes_ltc_ecb_encrypt's structure size.
 * 
 * Gladman AES is smaller for obvious reasons.
 */
#define CCDRBG_DF_BC_CBC_CTX_SIZE   0x200

struct ccdrbg_df_bc_ctx {
    CCDRBG_DF_COMMON;
    const struct ccmode_cbc *cbc;
    size_t key_nbytes;

    cc_ctx_decl_vla(cccbc_ctx, CCDRBG_DF_BC_CBC_CTX_SIZE, cbc_ctx);
};

/*
 * Block-Cipher Derivation Function only ever requires that
 */
CC_EXPORT
cc_error_t ccdrbg_df_bc_init(ccdrbg_df_bc_ctx_t *ctx,
                             const struct ccmode_cbc *cbc,
                             size_t key_nbytes);

CC_END_DECLS

#endif /* __CORECRYPTO_CCDRBG_DF_H__  */
