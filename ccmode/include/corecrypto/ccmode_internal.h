/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_INTERNAL_H__
#define __CORECRYPTO_CCMODE_INTERNAL_H__

#include <corecrypto/ccmode.h>
#include <corecrypto/ccn.h>

CC_BEGIN_DECLS

/*
 * Default CBC implementation.
 */
#define CCMODE_CBC_FACTORY(cipher, encdec)                                  \
    static struct ccmode_cbc cbc_##cipher##_##encdec;                       \
                                                                            \
    const struct ccmode_cbc *cc##cipher##_cbc_##encdec##(void) {            \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_##encdec##_mode();    \
        ccmode_factory_cbc_##encdec(&cbc_##cipher##_##encdec, ecb);         \
        return &cbc_##cipher##_##encdec;                                    \
    }                                                                       \

cc_error_t ccmode_cbc_init(const struct ccmode_cbc *cbc,
                           cccbc_ctx *ctx,
                           size_t rk_len,
                           const void *rk);

cc_error_t ccmode_cbc_decrypt(const cccbc_ctx *ctx,
                              cccbc_iv *iv,
                              size_t nblocks,
                              const void *in,
                              void *out);

cc_error_t ccmode_cbc_encrypt(const cccbc_ctx *ctx,
                              cccbc_iv *iv,
                              size_t nblocks,
                              const void *in,
                              void *out);

struct _ccmode_cbc_key {
    const struct ccmode_ecb *ecb;
    cc_unit u[];
};

#define CCMODE_CBC_KEY(key)         ((struct _ccmode_cbc_key *)key)
#define CCMODE_CBC_KEY_ECB(key)     CCMODE_CBC_KEY(key)->ecb
#define CCMODE_CBC_KEY_ECB_CTX(key) (ccecb_ctx *)(&CCMODE_CBC_KEY(key)->u[0])

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_INTERNAL_H__ */
