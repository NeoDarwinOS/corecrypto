/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto/cc_debug.h"
#include <corecrypto/cc_memory.h>
#include <corecrypto/cctest_symmetric.h>

static const char *cctest_symmetric_get_impl_name(const struct cctest_symmetric_impls *impl, cctest_symmetric_mode_t mode)
{
    switch (mode) {
        case CCTEST_SYMMETRIC_MODE_ECB:
            return impl->impls.ecb->impl_name;
    }
}

cc_error_t cctest_symmetric_run(const struct cctest_symmetric_test *self)
{
    cc_error_t result = CCERR_OK;

    for (size_t i = 0; i < self->nimpls; i++) {
        const struct cctest_symmetric_impls *impl = &self->impls[i];

        for (size_t j = 0; j < self->nvec; j++) {
            switch (self->mode) {
                case CCTEST_SYMMETRIC_MODE_ECB:
                    result = cctest_symmetric_ecb_do_vec(impl->impls.ecb, self->direction, &self->vecs[j]);
                    break;
            }

            if (result == CCERR_OK) {
                continue;
            } else {
                cc_debug_log("%s failed %s, vec: %zd", cctest_symmetric_get_impl_name(impl, self->mode), self->name, j+1);
                return result;
            }
        }
    }

    return result;
}

cc_error_t cctest_symmetric_ecb_do_vec(const struct ccmode_ecb *ecb,
                                       cctest_symmetric_direction_t direction,
                                       const struct cctest_symmetric_vector *vec)
{
    ccecb_ctx_decl(ccecb_context_size(ecb), ctx);
    size_t key_size = cctest_hex_string_to_data_len(vec->key);
    uint8_t *key = cctest_hex_string_to_data(vec->key);
    size_t pt_size = cctest_hex_string_to_data_len(vec->pt);
    uint8_t *pt = cctest_hex_string_to_data(vec->pt);
    size_t ct_size = cctest_hex_string_to_data_len(vec->ct);
    uint8_t *ct = cctest_hex_string_to_data(vec->ct);
    cc_error_t result = CCERR_OK;

    result = ccecb_init(ecb, ctx, key_size, key);
    if (result) {
        goto exit;
    }

    if (direction == CCTEST_SYMMETRIC_DIRECTION_ENCRYPT) {
        uint8_t *buffer = cc_heap_allocate(ct_size);

        ccecb_update(ecb, ctx, (pt_size / ecb->block_size), pt, buffer);

        result = (cc_cmp_safe(ct_size, ct, buffer) == 0) ? CCERR_OK : CCERR_INTEGRITY;

        cc_heap_free(buffer, ct_size);
    } else if (direction == CCTEST_SYMMETRIC_DIRECTION_DECRYPT) {
        uint8_t *buffer = cc_heap_allocate(ct_size);

        ccecb_update(ecb, ctx, (ct_size / ecb->block_size), ct, buffer);

        result = (cc_cmp_safe(ct_size, pt, buffer) == 0) ? CCERR_OK : CCERR_INTEGRITY;

        cc_heap_free(buffer, ct_size);
    }

exit:
    ccecb_ctx_clear(ccecb_context_size(ecb), ctx);
    cc_heap_free(key, key_size);
    cc_heap_free(pt, pt_size);
    cc_heap_free(ct, ct_size);
    return result;
}
