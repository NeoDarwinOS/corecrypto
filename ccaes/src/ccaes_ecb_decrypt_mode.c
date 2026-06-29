/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccaes.h>

const struct ccmode_ecb *ccaes_ecb_decrypt_mode(void)
{
    return &ccaes_ltc_ecb_decrypt_mode;
}
