/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_MACROS_H__
#define __CORECRYPTO_CC_MACROS_H__

//
// cc_macros.h:
//      AssertMacros style macros for corecrypto without explicitly depending on CarbonHeaders
//      This project needs to be cross-platform.
//

#define cc_require(assertion, label)                \
    if (__builtin_expect(!(assertion), 0)) {        \
        goto label;                                 \
    }

#endif /* __CORECRYPTO_CC_MACROS_H__ */

