/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCZP_H__
#define __CORECRYPTO_CCZP_H__

#include <corecrypto/ccn.h>

typedef struct cczp *cczp_t;
typedef const struct cczp *cczp_const_t;

/* This is actually not a public thing. "Reality can be whatever I want." */
typedef const struct cczp_funcs *cczp_funcs_t;

struct cczp {
    cc_size n;
    cc_unit bitlen;
    cc_unit u[];
};

#endif /* __CORECRYPTO_CCZP_H__  */
