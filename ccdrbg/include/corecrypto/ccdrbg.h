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
#include <corecrypto/ccdrbg_df.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

/*
 * API NOTES:
 *
 * These routines provide the skeleton for a fully featured DRBG. It does not cover everything.
 *
 * Prediction Resistance is a contract between the wrapper of the DRBG and the DRBG, where the DRBG
 * maintains a reseed counter, whilst periodic prediction breaking is handled by the wrapper.
 *
 * This API surface isn't actually used by any clients, so we can realistically modify it to suit our needs.
 *
 * CommonCrypto only ever calls ccrng, which is our internal DRBG.
 */

/*
 * SP800-90A excerpts:
 *
 * entropy_input: Input bits containing entropy. The maximum length of the entropy_input
 * is implementation dependent, but shall be less than or equal to the specified maximum
 * length for the selected DRBG mechanism (see Section 10).
 *
 * Hash based DRBGs are placed with a limit of AT MAXIMUM 2^35 bits, and so are CTR DRBGs.
 */
#define CCDRBG_MAX_ENTROPY_SIZE             (1 << 16)
#define CCDRBG_MAX_ADDITIONALINPUT_SIZE     (1 << 16)
#define CCDRBG_MAX_PSINPUT_SIZE             (1 << 16)
#define CCDRBG_MAX_REQUEST_SIZE             (1 << 16)   /* Hard limit from SP800-90A */
#define CCDRBG_RESEED_INTERVAL              (1ULL << 48)

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
size_t ccdrbg_context_size(const struct ccdrbg_info *info);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
ccdrbg_status_t ccdrbg_init(const struct ccdrbg_info *info,
                            struct ccdrbg_state *state,
                            size_t entropy_length,
                            const void *entropy,
                            size_t none_length,
                            const void *nonce,
                            size_t ps_length,
                            const void *ps);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
ccdrbg_status_t ccdrbg_reseed(const struct ccdrbg_info *info,
                              struct ccdrbg_state *state,
                              size_t entropy_length,
                              const void *entropy,
                              size_t ad_length,
                              const void *ad);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
ccdrbg_status_t ccdrbg_generate(const struct ccdrbg_info *info,
                                struct ccdrbg_state *state,
                                size_t out_length,
                                void *out,
                                size_t ad_length,
                                const void *ad);

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
void ccdrbg_done(const struct ccdrbg_info *info,
                 struct ccdrbg_state *state);

struct ccdrbg_nistctr_custom {
    const struct ccmode_ctr *ctr;
    size_t key_length;
    bool strictFIPS;
    ccdrbg_df_ctx_t *df_ctx;
};

CC_EXPORT
CORECRYPTO_API_AVAILABLE_2012
void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom);

//
// TODO: we need a HMAC DRBG for later ECC operations and key generation as per FIPS
//
struct ccdrbg_nisthmac_custom {
    const struct ccdigest_info *di;
    bool strictFIPS;
};

//
// optionally add Hash_DRBG? i doubt many places would use it but it would be useful for someone surely.
//

CC_END_DECLS

#endif /* __CORECRYPTO_CCDRBG_H__  */
