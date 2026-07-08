/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cctest_symmetric.h>

#include "ccaes_ecb_nist_kat.h"

const struct cctest_symmetric_test ccaes_ecb_nist_kat_encrypt = {
    .name = "ccaes NIST AESVS KAT",
    .run = &cctest_symmetric_run,
};
