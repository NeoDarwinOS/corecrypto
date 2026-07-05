/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


#ifndef __CORECRYPTO_CCRSA_H__
#define __CORECRYPTO_CCRSA_H__

#include <corecrypto/cczp.h>

/*
 * Layout of ccrsa_xxx_ctx:
 *
 * ccrsa_pub_ctx:
 *  [cczp header]
 *  cc_unit m[n_units]          <- Modulus
 *  cc_unit mr[n_units + 1]     <- Reciprocal of m
 *  cc_unit e[n_units]          <- Exponent
 *  cc_unit d[n_units]
 *
 * ccrsa_priv_ctx:
 *  [cczp header]
 *  cc_unit p[n_units / 2]              <- p component of private key
 *  cc_unit pr[(n_units / 2) + 1]       <- reciprocal of p
 *  [cczp header]
 *  cc_unit q[n_units / 2]              <- q component of private key
 *  cc_unit qr[(n_units / 2) + 1]       <- reciprocal of q
 *  cc_unit dp[n_units / 2]             <- d * p
 *  cc_unit dq[n_units / 2]             <- d * q
 *  cc_unit qinv[n_units / 2]           <- inverse of q
 *
 * ccrsa_full_ctx:
 *  [ccrsa_pub_ctx]
 *  [ccrsa_priv_ctx]
 */

struct ccrsa_pub_ctx {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

typedef struct ccrsa_pub_ctx *ccrsa_pub_ctx_t;

struct ccrsa_priv_ctx {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

typedef struct ccrsa_priv_ctx *ccrsa_priv_ctx_t;

struct ccrsa_full_ctx {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

typedef struct ccrsa_full_ctx *ccrsa_full_ctx_t;

#endif /* __CORECRYPTO_CCRSA_H__ */
