/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccblowfish.h>
#include <corecrypto/ccmode_internal.h>

// might as well just have these here. we don't use any other impls.
const struct ccmode_ecb *ccblowfish_ecb_encrypt_mode(void) {
    return &ccblowfish_ltc_ecb_encrypt_mode;
}

const struct ccmode_ecb *ccblowfish_ecb_decrypt_mode(void) {
    return &ccblowfish_ltc_ecb_decrypt_mode;
}

CCMODE_CBC_FACTORY(blowfish, encrypt);
CCMODE_CBC_FACTORY(blowfish, decrypt);
CCMODE_CTR_FACTORY(blowfish);
