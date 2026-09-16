/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccrc2.h>
#include <corecrypto/ccmode_internal.h>

// might as well just have these here. we don't use any other impls.
const struct ccmode_ecb *ccrc2_ecb_encrypt_mode(void) {
    return &ccrc2_ltc_ecb_encrypt_mode;
}

const struct ccmode_ecb *ccrc2_ecb_decrypt_mode(void) {
    return &ccrc2_ltc_ecb_decrypt_mode;
}

CCMODE_CBC_FACTORY(rc2, encrypt);
CCMODE_CBC_FACTORY(rc2, decrypt);
CCMODE_CTR_FACTORY(rc2);
