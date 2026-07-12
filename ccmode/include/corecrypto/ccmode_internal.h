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

CC_INLINE void inc_uint_be(uint8_t *ptr, size_t len)
{
    for (size_t i = 1; i <= len; i += 1) {
        size_t j = len - i;
        ptr[j] = (uint8_t)(ptr[j] + 1);
        if (ptr[j] > 0) {
            return;
        }
    }
}

/*
 * Default CBC implementation.
 */
#define CCMODE_CBC_FACTORY(cipher, encdec)                                  \
    static struct ccmode_cbc cbc_##cipher##_##encdec;                       \
                                                                            \
    const struct ccmode_cbc *cc##cipher##_cbc_##encdec##_mode(void) {       \
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

/*
 * Default CTR implementation
 */
#define CCMODE_CTR_FACTORY(cipher)                                          \
    static struct ccmode_ctr ctr_##cipher;                                  \
                                                                            \
    const struct ccmode_ctr *cc##cipher##_ctr_crypt_mode(void) {            \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_encrypt_mode();       \
        ccmode_factory_ctr_crypt(&ctr_##cipher, ecb);                       \
        return &ctr_##cipher;                                               \
    }                                                                       \

struct _ccmode_ctr_key {
    const struct ccmode_ecb *ecb;
    size_t pad_len;

    /*
     * layout:
     * counter  [ block_size ]
     * pad      [ block_size ]
     * ecb_ctx  [ ecb ctx size ]
     */
    cc_unit u[];
};

cc_error_t ccmode_ctr_init(const struct ccmode_ctr *ctr,
                           ccctr_ctx *ctx,
                           size_t key_size,
                           const void *key,
                           const void *iv);

cc_error_t ccmode_ctr_setctr(const struct ccmode_ctr *ctr,
                             ccctr_ctx *ctx,
                             const void *counter);

cc_error_t ccmode_ctr_crypt(ccctr_ctx *ctx,
                            size_t nbytes,
                            const void *in,
                            void *out);

#define CCMODE_CTR_KEY(key)             ((struct _ccmode_ctr_key *)key)
#define CCMODE_CTR_KEY_ECB(key)         CCMODE_CTR_KEY(key)->ecb
#define CCMODE_CTR_KEY_COUNTER(key)     (uint8_t *)(&CCMODE_CTR_KEY(key)->u[0])
#define CCMODE_CTR_KEY_PAD_LENGTH(key)  (CCMODE_CTR_KEY(key)->pad_len)
#define CCMODE_CTR_KEY_PAD(key)         (uint8_t *)(&CCMODE_CTR_KEY(key)->u[ccn_nof_size(CCMODE_CTR_KEY_ECB(key)->block_size)])
#define CCMODE_CTR_KEY_ECB_CTX(key)     (ccecb_ctx *)(&CCMODE_CTR_KEY(key)->u[ccn_nof_size(CCMODE_CTR_KEY_ECB(key)->block_size * 2)])

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_INTERNAL_H__ */
