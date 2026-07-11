/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDRBG_H__
#define __CORECRYPTO_CCDRBG_H__

#include <corecrypto/cc.h>
#include <corecrypto/ccdrbg_impl.h>
#include <corecrypto/ccmode.h>

CC_BEGIN_DECLS

/*
 * API NOTES:
 *
 * These routines provide the skeleton for a fully featured DRBG. It does not cover everything.
 *
 * For example, for predicition resistence, this is implemented by the API making use of the underlying DRBG code.
 */

/*
 * SP800-90A excerpts:
 *
 * entropy_input: Input bits containing entropy. The maximum length of the entropy_input
 * is implementation dependent, but shall be less than or equal to the specified maximum
 * length for the selected DRBG mechanism (see Section 10).
 *
 * Hash based DRBGs are placed with a limit of AT MAXIMUM 2^35 bits, and so are CTR DRBGs.
 *
 * For simplicity's sake, and to make this portable for armv7 and i386 (because I know someone will want to),
 * let's strive for under the 32-bit integer limit and use (1 << 30) as our base.
 *
 * CTR_DRBG is annoying and places it's limit at seedlen when used without a derivation function.
 *
 * Anyways, the bitshift right now works in bits. I need to reduce the bitshift size
 */
#define CCDRBG_MAX_ENTROPY_SIZE             (1 << 31)
#define CCDRBG_MAX_ADDITIONALINPUT_SIZE     (1 << 31)
#define CCDRBG_MAX_PSINPUT_SIZE             (1 << 31)
#define CCDRBG_MAX_REQUEST_SIZE             (1 << 16)   /* Hard limit from SP800-90A */
#define CCDRBG_RESEED_INTERVAL              (1 << 48)

CC_EXPORT
size_t ccdrbg_context_size(const struct ccdrbg_info *info);

CC_EXPORT
ccdrbg_status_t ccdrbg_init(const struct ccdrbg_info *info,
                            struct ccdrbg_state *state,
                            size_t entropy_length,
                            const void *entropy,
                            size_t none_length,
                            const void *nonce,
                            size_t ps_length,
                            const void *ps);

CC_EXPORT
ccdrbg_status_t ccdrbg_reseed(const struct ccdrbg_info *info,
                              struct ccdrbg_state *state,
                              size_t entropy_length,
                              const void *entropy,
                              size_t ad_length,
                              const void *ad);

CC_EXPORT
ccdrbg_status_t ccdrbg_generate(const struct ccdrbg_info *info,
                                struct ccdrbg_state *state,
                                size_t out_length,
                                void *out,
                                size_t ad_length,
                                const void *ad);

CC_EXPORT
ccdrbg_status_t ccdrbg_done(const struct ccdrbg_info *info,
                            struct ccdrbg_state *state);

struct ccdrbg_nistctr_custom {
    const struct ccmode_ctr *ctr;
    size_t key_length;
    bool strictFIPS;
    bool use_df;
};

CC_EXPORT
void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom);

CC_END_DECLS

#endif /* __CORECRYPTO_CCDRBG_H__  */
