/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_H__
#define __CORECRYPTO_CCMODE_H__

#include <corecrypto/ccmode_impl.h>
#include <corecrypto/ccmode_factory.h>

CC_BEGIN_DECLS

/*
 * Useful macros
 */

/* Currently 16 for AES. Change when required. */
#define CCMODE_MAX_BLOCK_SIZE   16


/*
 * ECB mode declarations
 */
#define ccecb_ctx_decl(size, name) cc_ctx_decl(ccecb_ctx, size, name)
#define ccecb_ctx_clear(size, name) cc_clear(size, name)

CC_EXPORT
size_t ccecb_context_size(const struct ccmode_ecb *ecb);

CC_EXPORT
size_t ccecb_block_size(const struct ccmode_ecb *ecb);

CC_EXPORT
cc_error_t ccecb_init(const struct ccmode_ecb *ecb,
                      ccecb_ctx *ctx,
                      size_t key_size,
                      const void *key);

CC_EXPORT
cc_error_t ccecb_update(const struct ccmode_ecb *ecb,
                        const ccecb_ctx *ctx,
                        size_t nblocks,
                        const void *in,
                        void *out);

CC_EXPORT
cc_error_t ccecb_one_shot(const struct ccmode_ecb *ecb,
                          size_t key_length,
                          const void *key,
                          size_t nblocks,
                          const void *in,
                          void *out);


#define cccbc_ctx_decl(size, name) cc_ctx_decl(cccbc_ctx, size, name)
#define cccbc_ctx_clear(size, name) cc_clear(size, name)

#define cccbc_iv_decl(size, name) cc_ctx_decl(cccbc_iv, size, name)
#define cccbc_iv_clear(size, name) cc_clear(size, name)

CC_EXPORT
size_t cccbc_context_size(const struct ccmode_cbc *cbc);

CC_EXPORT
size_t cccbc_block_size(const struct ccmode_cbc *cbc);

CC_EXPORT
cc_error_t cccbc_init(const struct ccmode_cbc *cbc,
                      cccbc_ctx *ctx,
                      size_t key_size,
                      const void *key);

CC_EXPORT
cc_error_t cccbc_set_iv(const struct ccmode_cbc *mode,
                        cccbc_iv *iv_ctx,
                        const void *iv);

CC_EXPORT
cc_error_t cccbc_update(const struct ccmode_cbc *cbc,
                        const cccbc_ctx *ctx,
                        cccbc_iv *iv,
                        size_t nblocks,
                        const void *in,
                        void *out);

CC_EXPORT
cc_error_t cccbc_one_shot(const struct ccmode_cbc *cbc,
                          size_t key_length,
                          const void *key,
                          size_t nblocks,
                          const void *iv,
                          const void *in,
                          void *out);

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_H__ */
