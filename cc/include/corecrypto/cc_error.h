/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_ERROR_H__
#define __CORECRYPTO_CC_ERROR_H__

/* Likely going to back the APIs with an integer return code. */
typedef int cc_error_t;

/* Error result codes */
#define CCERR_OK                0
#define CCERR_INTERNAL          -1
#define CCERR_INTEGRITY         -2
#define CCERR_DEVICE            -3
#define CCERR_INTERRUPTS        -4
#define CCERR_CRYPTO_CONFIG     -5
#define CCERR_PERMS             -6
#define CCERR_PARAMETER         -7
#define CCERR_MEMORY            -8
#define CCERR_FILEDESC          -9
#define CCERR_OUT_OF_ENTROPY    -10
#define CCERR_ATFORK            -11
#define CCERR_OVERFLOW          -12

#endif /* __CORECRYPTO_CC_ERROR_H__ */
