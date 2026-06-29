/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCN_H__
#define __CORECRYPTO_CCN_H__

#include <corecrypto/cc.h>

#define ccn_sizeof_n(n)         (sizeof(cc_unit) * (n))
#define ccn_nof(bits)           (((bits) + CC_UNIT_BITS - 1) >> CC_LOG2_BITS_PER_UNIT)
#define ccn_sizeof(bits)        (ccn_sizeof_n(ccn_nof(bits)))
#define ccn_nof_size(size)      (((size) + CC_UNIT_SIZE - 1) / CC_UNIT_SIZE)
#define ccn_nof_sizeof(type)    ccn_nof_size(sizeof(type))
#define ccn_bitsof_n(n)         ((n) * CC_UNIT_BITS)
#define ccn_bitsof_size(size)   ((size) * 8)
#define ccn_sizeof_size(size)   ccn_sizeof_n(ccn_nof_size(size))

#define ccn_bit(ccn, k) ({                                                          \
        __typeof__(k) _k = (k);                                                     \
        1 & ((ccn)[_k >> CC_LOG2_BITS_PER_UNIT] >> (_k & (CC_UNIT_BITS - 1)));      \
    })

#define ccn_set_bit(ccn, k, v) ({                                                               \
    __typeof__(k) _k = (k);                                                                     \
    if (v)                                                                                      \
        (ccn)[ _k >> CC_LOG2_BITS_PER_UNIT] |= CC_UNIT_C(1) << (_k & (CC_UNIT_BITS - 1));       \
    else                                                                                        \
        (ccn)[ _k >> CC_LOG2_BITS_PER_UNIT] &= ~(CC_UNIT_C(1) << (_k & (CC_UNIT_BITS - 1)));    \
    })


#endif /* __CORECRYPTO_CCN_H__  */
