/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>

#if CC_PLATFORM_XNU

#include <kern/debug.h>

void cc_abort(const char *msg)
{
    panic("corecrypto: %s", msg);
}

#else

#include <stdlib.h>
#include <stdio.h>

void cc_abort(const char *msg)
{
    fprintf(stderr, "corecrypto: %s\n", msg);
    abort();
}

#endif
