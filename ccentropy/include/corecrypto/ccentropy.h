/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCENTROPY_H__
#define __CORECRYPTO_CCENTROPY_H__

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>

typedef struct ccentropy_ctx *ccentropy_ctx_t;

struct ccentropy_info {
    cc_error_t (*get_seed)(ccentropy_ctx_t ctx,
                           size_t nbytes,
                           void *seed);
    
    cc_error_t (*add_entropy)(ccentropy_ctx_t ctx,
                              uint32_t nsamples,
                              size_t nbytes,
                              const void *entropy);
};

struct ccentropy_ctx {
    const struct ccentropy_info *ei;
};

//
// Specialised entropy managers begin here.
//

//
// Digest.
//
struct ccentropy_digest_ctx {
    const struct ccentropy_info *ei;
    const struct ccdigest_info *di;
    ccdigest_ctx_decl_vla(CCDIGEST_MAX_STATE_SIZE,
                          CCDIGEST_MAX_BLOCK_SIZE,
                          digest);
};

#endif /* __CORECRYPTO_CCENTROPY_H__ */
