/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccpost_internal.h"

#define CCPOST_RUN_FUNCTION(x) ({            \
        cc_post_log(#x " ENTER");            \
        cc_error_t err = x();               \
        if (err) {                          \
            cc_post_log(#x " FAIL");         \
            return err;                     \
        } else {                            \
            cc_post_log(#x " PASS");         \
        }                                   \
        err;                                \
    })

#include "ccpost_internal.h"

cc_error_t ccpost_validate(void)
{
    cc_error_t err = CCERR_OK;
    size_t nfails;
    cc_post_log("BEGINNING PREFLIGHT TESTS.");

    err = CCPOST_RUN_FUNCTION(ccpost_aes_ecb_validate);

    if (err == CCERR_OK) {
        cc_post_log("ALL TESTS PASS");
    }

    return err;
}
