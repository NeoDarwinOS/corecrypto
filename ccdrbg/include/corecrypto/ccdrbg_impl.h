/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDRBG_IMPL_H__
#define __CORECRYPTO_CCDRBG_IMPL_H__

#include <corecrypto/cc.h>

struct ccdrbg_state;

struct ccdrbg_info {
    size_t size;

    ccdrbg_status_t (*init)(const struct ccdrbg_info *info,
                            struct ccdrbg_state *state,
                            size_t entropy_length,
                            const void *entropy,
                            size_t nonce_length,
                            const void *nonce,
                            size_t ps_length,
                            const void *ps);

    ccdrbg_status_t (*reseed)(struct ccdrbg_state *state,
                              size_t entropy_length,
                              const void *entropy,
                              size_t ad_length,
                              const void *ad);

    ccdrbg_status_t (*generate)(struct ccdrbg_state *state,
                                size_t out_length,
                                void *out,
                                size_t ad_length,
                                const void *ad);

    void (*done)(struct ccdrbg_state *state);

    const void *custom;
};

#endif /* __CORECRYPTO_CCDRBG_IMPL_H__  */
