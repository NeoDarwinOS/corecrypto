/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto/cc_absolute_time.h"
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_lock.h>

/*
 * NOTE: This is not finished! This is the groundwork for the global RNG once the CTR DRBG is finalised.
 */

#if CC_PLATFORM_DARWIN && CC_SHARED_LIBRARY
//
// libSystem will call various functions.
//
// These handle prediction resistance, which we DO NOT do yet.
//
#define LIBSYSTEM_CALLS_FORK_FUNCTIONS  1
#else
#define LIBSYSTEM_CALLS_FORK_FUNCTIONS  0
#endif

static
cc_error_t ccrng_crypto_getentropy(size_t nbytes, void *buffer);

#if CC_PLATFORM_XNU

#include <sys/random.h>
#include <sys/types.h>
#include <machine/limits.h>

cc_error_t ccrng_crypto_getentropy(size_t nbytes, void *buffer)
{
    cc_internal_crash(nbytes > UINT_MAX, "getentropy nbytes > UINT_MAX");
    read_random(buffer, (u_int)nbytes);
    return CCERR_OK;
}

#elif CC_PLATFORM_LINUX || CC_PLATFORM_DARWIN

#include <sys/random.h>

cc_error_t ccrng_crypto_getentropy(size_t nbytes, void *buffer)
{
    cc_internal_crash(nbytes > 256, "getentropy nbytes > 256");
    return getentropy(buffer, nbytes);
}

#endif

static
cc_error_t ccrng_crypto_rng_generate(struct ccrng_state *state, size_t nbytes, void *out);

#define CCRNG_SYSTEM_RNG_MAGIC 0xCC524E47

struct ccrng_crypto_rng {
    uint32_t magic;
    bool did_init;
    bool prediction_break;
    cc_lock_t rng_lock;
    struct ccdrbg_info drbg_info;
    struct ccdrbg_nistctr_custom drbg_custom;
    struct ccdrbg_df_bc_ctx drbg_df_bc_ctx;

    uint8_t drbg_state_buffer[1300];
    
    struct ccdrbg_state *drbg_state;
    
    struct ccrng_state rng_state;
};

static struct ccrng_crypto_rng __rng = {CCRNG_SYSTEM_RNG_MAGIC, false};

//
// !!!TEMPORARY!!!
//
static const uint8_t df_pr_entropy[] = "\x53\x43\x46\xa3\xe0\xba\xa6\x5d\x7a\x51\x87\x1b\x6d\x63\x3a\x6f\x1e\xfa\x9f\xf5\x5d\xfd\xe3\x21\x2c\x95\x02\x9a\xdf\x23\x87\xd9";

cc_error_t ccrng_crypto_rng_init_once(void) {
    cc_error_t err = CCERR_OK;
    
    if (__rng.did_init) {
        return CCERR_OK;
    }
    
    /* It's probably safer to abort here than not. */
    cc_internal_crash(__rng.magic == CCRNG_SYSTEM_RNG_MAGIC, "ccrng_crypto_rng: internal RNG structure is bad.");
    
    err = ccdrbg_df_bc_init(&__rng.drbg_df_bc_ctx, ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_256);
    cc_internal_crash(err != CCERR_OK, "ccdrbg_df_bc_init failed.");
    
    __rng.drbg_custom.ctr = ccaes_ctr_crypt_mode();
    __rng.drbg_custom.key_length = CCAES_KEY_SIZE_256;
    // --- this will only work on one thread for so long... --- //
    __rng.drbg_custom.strictFIPS = true;
    __rng.drbg_custom.df_ctx = (ccdrbg_df_ctx_t *)&__rng.drbg_df_bc_ctx;

    /* create a lock. we'll need it. */
    cc_lock_init(&__rng.rng_lock, "ccrng");
    
    __rng.drbg_state = (struct ccdrbg_state *)&__rng.drbg_state_buffer[0];

    ccdrbg_factory_nistctr(&__rng.drbg_info, &__rng.drbg_custom);
    cc_internal_crash(__rng.drbg_info.size == 0, "DRBG did not instantiate correctly");
    cc_internal_crash(__rng.drbg_info.size > sizeof(__rng.drbg_state_buffer), "DRBG is too large for our buffer. This is not good.");
    
    uint64_t now = cc_absolute_time();

    err = ccdrbg_init(&__rng.drbg_info, __rng.drbg_state,
                      sizeof(df_pr_entropy)-1, df_pr_entropy,
                      sizeof(now), &now,
                      sizeof("corecrypto rng")-1, "corecrypto rng");

    cc_internal_crash(err != CCERR_OK, "ccdrbg_init failed.");

    __rng.rng_state.generate = &ccrng_crypto_rng_generate;
    
    __rng.did_init = true;
    
    return CCERR_OK;
}

static
cc_error_t ccrng_crypto_rng_generate(struct ccrng_state *state, size_t nbytes, void *out)
{
    cc_lock_lock(&__rng.rng_lock);
    
    //
    // TODO: !!!PREDICTION RESISTANCE!!!
    //
    ccdrbg_generate(&__rng.drbg_info, __rng.drbg_state, nbytes, out, 0, NULL);
    
    cc_lock_unlock(&__rng.rng_lock);
    
    return CCERR_OK;
}

//
// !!!TEMPORARY!!! !!!WE SHOULD USE ACTUAL MULTITHREADING LIBRARIES SOON!!!
//
struct ccrng_state *
ccrng(cc_error_t *err)
{
    ccrng_crypto_rng_init_once();
    return &__rng.rng_state;
}
