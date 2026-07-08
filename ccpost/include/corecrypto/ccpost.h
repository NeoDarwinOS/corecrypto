/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCPOST_H__
#define __CORECRYPTO_CCPOST_H__

#include <corecrypto/cc.h>

/*!
 * @function ccpost_validate
 *
 * @discussion
 * This runs a self-instantiated integrity test on corecrypto, which a client app (ex: a boot task) can use
 * to quickly verify that everything is fine and dandy on boot.
 *
 * This is a less comprehensive test than the ones provided in cctest, but should cover all bases.
 */
cc_error_t ccpost_validate(void);

#endif /* __CORECRYPTO_CCPOST_H__ */
