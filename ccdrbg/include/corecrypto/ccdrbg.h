/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDRBG_H__
#define __CORECRYPTO_CCDRBG_H__

#include <corecrypto/cc.h>
#include <corecrypto/ccdrbg_impl.h>

/*
 * SP800-90A excerpts:
 *
 * entropy_input: Input bits containing entropy. The maximum length of the entropy_input
 * is implementation dependent, but shall be less than or equal to the specified maximum
 * length for the selected DRBG mechanism (see Section 10).
 *
 * Hash based DRBGs are placed with a limit of 2^35 bits, and so are CTR DRBGs.
 *
 * For simplicity's sake, and to make this portable for armv7 and i386 (because I know someone will want to),
 * let's strive for under the 32-bit integer limit and use (1 << 30) as our base.
 *
 * CTR_DRBG is annoying and places it's limit at seedlen when used without a derivation function.
 *
 * Anyways, the bitshift right now works in bits. I need to reduce the bitshift size
 */
#define CCDRBG_MAX_ENTROPY_SIZE             (1 << 19)
#define CCDRBG_MAX_ADDITIONALINPUT_SIZE     (1 << 30)

#endif /* __CORECRYPTO_CCDRBG_H__  */
