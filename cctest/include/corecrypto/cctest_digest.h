/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCTEST_DIGEST_H__
#define __CORECRYPTO_CCTEST_DIGEST_H__

#include <corecrypto/ccmode.h>
#include <corecrypto/cctest_base.h>

/* digests are a lot simpler. throw an input, get an output. */

struct cctest_digest_vector {
    const char *in;
    const char *out;
};

#endif /* __CORECRYPTO_CCTEST_DIGEST_H__ */
