/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto_kext_if.h"

kern_return_t corecrypto_start(kmod_info_t * ki, void *d);
kern_return_t corecrypto_stop(kmod_info_t *ki, void *d);

kern_return_t corecrypto_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t corecrypto_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
