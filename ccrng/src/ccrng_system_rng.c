/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_lock.h>

/*
 * NOTE: This is not finished! This is the groundwork for the global RNG once the CTR DRBG is finalised.
 */

#if CC_PLATFORM_DARWIN && CC_SHARED_LIBRARY
#define LIBSYSTEM_CALLS_FORK_FUNCTIONS  1
#else
#define LIBSYSTEM_CALLS_FORK_FUNCTIONS  0
#endif

#define CCRNG_SYSTEM_RNG_MAGIC 0xCC524E47

struct ccrng_system_rng {
    uint32_t magic;
    bool prediction_break;
    cc_lock_t rng_lock;
    struct ccdrbg_info drbg_info;
    struct ccdrbg_nistctr_custom drbg_custom;

    uint8_t drbg_state_buffer[1000];
};

static struct ccrng_system_rng __rng = {CCRNG_SYSTEM_RNG_MAGIC};

cc_error_t ccrng_system_rng_init_once(void) {
    /* It's probably safer to abort here than not. */
    cc_internal_crash(__rng.magic == CCRNG_SYSTEM_RNG_MAGIC, "ccrng_system_rng: internal RNG structure is bad.");

    __rng.drbg_custom.ctr = ccaes_ctr_crypt_mode();
    __rng.drbg_custom.key_length = CCAES_KEY_SIZE_256;
    __rng.drbg_custom.strictFIPS = true;
    __rng.drbg_custom.use_df = true;

    /* create a lock. we'll need it. */
    cc_lock_init(&__rng.rng_lock, "ccrng");

    ccdrbg_factory_nistctr(&__rng.drbg_info, &__rng.drbg_custom);
    cc_internal_crash(__rng.drbg_info.size == 0, "DRBG did not instantiate correctly");
    cc_internal_crash(__rng.drbg_info.size > sizeof(__rng.drbg_state_buffer), "DRBG is too large for our buffer. This is not good.");

    return CCERR_OK;
}
