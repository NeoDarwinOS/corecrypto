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
 *
 * cc_boot_post as an executable should dlsym into this library rather than directly linking.
 */
cc_error_t ccpost_validate(void);

/*!
 * @function ccpost_print_runtime
 *
 * @discussion
 * This is a function that is primarily designed to diagnose environments where POSTs have failed.
 *
 * It will be able to quickly dump what digest and cipher implementations are being used.
 */
void ccpost_print_runtime(void);

#endif /* __CORECRYPTO_CCPOST_H__ */
