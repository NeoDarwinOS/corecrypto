/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCKPRNG_H__
#define __CORECRYPTO_CCKPRNG_H__

#include <corecrypto/cc_compatibility.h>

CC_BEGIN_DECLS

//
// The Kernel PRNG for Darwin 19 is a modified Fortuna construction with some interesting details:
//  - There is more than one constructed generator
//  - There are 32 pools, however each generator context has two keys: a live and an inactive key
//
// It's worthy of note that later revisions of Darwin switched to using the Fortuna PRNG as source of entropy for a CTR DRBG.
//

#define CCKPRNG_NPOOLS          32
#define CCKPRNG_SEED_NBYTES     32
#define CCKPRNG_POOL_NBYTES     32
#define CCKPRNG_KEY_NBYTES      32

#if CC_COMPATIBILITY_TARGETS(DARWIN_19) || CC_COMPATIBILITY_TARGETS(DARWIN_20) || CC_COMPATIBILITY_TARGETS(DARWIN_21)
#define CCKPRNG_BACKEND_FORTUNA_MULTI_GEN   1
#endif

#if CCKPRNG_BACKEND_FORTUNA_MULTI_GEN

#endif

CC_END_DECLS

#endif /* __CORECRYPTO_CCKPRNG_H__  */
