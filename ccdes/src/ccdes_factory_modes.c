/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode_internal.h>

CCMODE_CBC_FACTORY(des, encrypt);
CCMODE_CBC_FACTORY(des, decrypt);
CCMODE_CTR_FACTORY(des);
