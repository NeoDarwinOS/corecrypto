/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdrbg.h>

size_t ccdrbg_context_size(const struct ccdrbg_info *info)
{
    return info->size;
}

ccdrbg_status_t ccdrbg_init(const struct ccdrbg_info *info,
                            struct ccdrbg_state *state,
                            size_t entropy_length,
                            const void *entropy,
                            size_t nonce_length,
                            const void *nonce,
                            size_t ps_length,
                            const void *ps)
{
    return info->init(info, state, entropy_length, entropy, nonce_length, nonce, ps_length, ps);
}

ccdrbg_status_t ccdrbg_reseed(const struct ccdrbg_info *info,
                              struct ccdrbg_state *state,
                              size_t entropy_length,
                              const void *entropy,
                              size_t ad_length,
                              const void *ad)
{
    return info->reseed(state, entropy_length, entropy, ad_length, ad);
}

ccdrbg_status_t ccdrbg_generate(const struct ccdrbg_info *info,
                                struct ccdrbg_state *state,
                                size_t out_length,
                                void *out,
                                size_t ad_length,
                                const void *ad)
{
    return info->generate(state, out_length, out, ad_length, ad);
}

void ccdrbg_done(const struct ccdrbg_info *info,
                 struct ccdrbg_state *state)
{
    info->done(state);
}
