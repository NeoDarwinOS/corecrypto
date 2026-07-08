/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCTEST_SYMMETRIC_H__
#define __CORECRYPTO_CCTEST_SYMMETRIC_H__

#include <corecrypto/ccmode.h>
#include <corecrypto/cctest_base.h>

typedef enum cctest_symmetric_mode {
    CCTEST_SYMMETRIC_MODE_ECB,
} cctest_symmetric_mode_t;

typedef enum cctest_symmetric_direction {
    CCTEST_SYMMETRIC_DIRECTION_ENCRYPT,
    CCTEST_SYMMETRIC_DIRECTION_DECRYPT,
} cctest_symmetric_direction_t;

struct cctest_symmetric_vector {
    const char *key;
    const char *pt;
    const char *ct;

    /* extra components */
    const char *iv;

    /* This is for future GCM/CCM impls. */
    const char *aad;
};

struct cctest_symmetric_impls {
    union {
        const struct ccmode_ecb *ecb;
        const struct ccmode_cbc *cbc;
    } impls;
};

struct cctest_symmetric_test {
    /* cctest_base fields */
    const char *name;

    /* instead of using cctest_base, it's easier to just use cctest_symmetric_test */
    cc_error_t (*run)(const struct cctest_symmetric_test *self);

    /* symmetric fields */
    cctest_symmetric_mode_t mode;
    cctest_symmetric_direction_t direction;

    size_t nvec;
    const struct cctest_symmetric_vector *vecs;

    /* test multiple implementations of the same mode at once */
    size_t nimpls;
    const struct cctest_symmetric_impls *impls;
};

cc_error_t cctest_symmetric_run(const struct cctest_symmetric_test *self);

cc_error_t cctest_symmetric_ecb_do_vec(const struct ccmode_ecb *ecb,
                                       cctest_symmetric_direction_t direction,
                                       const struct cctest_symmetric_vector *vec);

cc_error_t cctest_symmetric_cbc_do_vec(const struct ccmode_cbc *cbc,
                                       cctest_symmetric_direction_t direction,
                                       const struct cctest_symmetric_vector *vec);

#endif /* __CORECRYPTO_CCTEST_SYMMETRIC_H__ */
