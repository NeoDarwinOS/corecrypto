/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCSHA1_INTERNAL_H__
#define __CORECRYPTO_CCSHA1_INTERNAL_H__

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccdigest_internal.h>

CC_BEGIN_DECLS

CC_PRIVATE
const uint32_t ccsha1_initial_state[5];

CC_END_DECLS

#endif /* __CORECRYPTO_CCSHA1_INTERNAL_H__ */
