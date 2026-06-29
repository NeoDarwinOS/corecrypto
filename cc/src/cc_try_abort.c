/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>

#if CC_PLATFORM_DARWIN || CC_PLATFORM_XNU || CC_PLATFORM_LINUX

void cc_try_abort(const char *msg) {
    cc_abort(msg);
}

#else

void cc_try_abort(const char *msg)
{
    (void)msg;
}

#endif
