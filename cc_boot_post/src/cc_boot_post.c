/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccpost.h>

int main(int argc, const char *argv[])
{
    if (ccpost_validate() == CCERR_OK) {
        return 0;
    } else {
        return -1;
    }
}
