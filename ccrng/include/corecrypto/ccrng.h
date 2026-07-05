/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCRNG_H__
#define __CORECRYPTO_CCRNG_H__

#include <corecrypto/cc.h>

CC_BEGIN_DECLS

struct ccrng_state {
    cc_error_t (*generate)(struct ccrng_state *rng,
                           size_t out_length,
                           void *out);
};

CC_EXPORT
struct ccrng_state *ccrng(cc_error_t *error);

#define ccrng_generate(rng, out_length, out)                            \
    ((rng)->generate((struct ccrng_state *)(rng), (out_length), (out)))

CC_END_DECLS

#endif /* __CORECRYPTO_CCRNG_H__  */
