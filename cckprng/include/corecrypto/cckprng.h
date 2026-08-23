/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCKPRNG_H__
#define __CORECRYPTO_CCKPRNG_H__

#include <corecrypto/cc.h>
#include <corecrypto/cc_compatibility.h>
#include <corecrypto/cc_lock.h>

CC_BEGIN_DECLS

//
// For kernel SPI, we need to export this header ourself.
//
// Make sure that corecrypto_kext in the Xcode project exports this.
//

//-------------------------------------------------
// OS-related configuration goes here
//-------------------------------------------------

//
// Controls whether or not the function pointers are NATIVE to cckprng.
//
// Darwin 18 defines the KPI contract in <prng/random.h>
//
#define CCKPRNG_OS_USES_BUILTIN_FUNCTION_POINTERS __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_15, __MAC_28_0)

//
// Defines whether the Fortuna backend is the system default.
//
#define CCKPRNG_OS_USES_FORTUNA_BACKEND __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_15, __MAC_13_0)

//
// Defines whether the kprng requires the entropybuffer shared interface.
//
#define CCKPRNG_OS_USES_ENTROPY_BUFFER __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_15, __MAC_28_0)

//
// Defines whether the kprng requires the getentropy function pointer.
//
#define CCKPRNG_OS_USES_GETENTROPY __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_11_1, __MAC_28_0)

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

//
// This backend was used by Apple between 2019 and 2022 release cycles.
//
#if CCKPRNG_OS_USES_FORTUNA_BACKEND
    #define CCKPRNG_BACKEND_FORTUNA_MULTI_GEN   1
#endif

//
// This abstraction is used beyond Fortuna
//
#if CCKPRNG_OS_USES_ENTROPY_BUFFER
struct cckprng_entropybuf {
    const void *buf;
    size_t nbytes;
    const uint32_t *n_samples;
    uint32_t n_samples_last;
};
#endif

//
// Per-OS function declarations
//
#if CCKPRNG_OS_USES_GETENTROPY
typedef int32_t (*cckprng_getentropy)(size_t *entropy_nbytes,
                                      void *entropy,
                                      void *arg);
#endif

#if CCKPRNG_BACKEND_FORTUNA_MULTI_GEN

#if (CCKPRNG_OS_USES_BUILTIN_FUNCTION_POINTERS == 0) && (CCKPRNG_OS_USES_ENTROPY_BUFFER == 0)
#error cckprng has somehow ended up misconfigured, fixme!!!
#endif

//
// This is a re-implementation of Apple's multi-generator Fortuna deisgn.
//
// It's... uh, something, to say the least.
//
struct cckprng_gen_diag {
    // # rekeys
    uint64_t n_rekeys;

    // # requests fulfilled
    uint64_t out_nreqs;

    // # bytes outputted
    uint64_t out_nbytes;

    // # maximum num bytes generated in on request
    uint64_t out_nbytes_req_max;

    // # num bytes since last rekey
    uint64_t out_nbytes_key;

    // total # bytes generated between two rekeys
    uint64_t out_nbytes_key_max;
};

struct cckprng_pool_diag {
    uint64_t n_samples;
    uint64_t n_drains;
    uint64_t n_samples_max;
};

struct cckprng_diag {
    uint64_t user_reseed_nreseeds;
    uint64_t sched_reseed_nreseeds;

    uint64_t sched_reseed_nsamples_max;
    uint64_t addentropy_nsamples_max;

    uint32_t ngens;
    struct cckprng_gen_diag *gens;

    struct cckprng_pool_diag pools[CCKPRNG_NPOOLS];
};

struct cckprng_key_ctx {
    uint8_t data[CCKPRNG_KEY_NBYTES];
};

struct cckprng_gen_ctx {
    struct cckprng_key_ctx keys[2];
    _Atomic uint32_t swap;
    uint32_t key_live_idx;
    uint32_t key_idle_idx;

    uint8_t ctr[16];

    bool init;

    cc_lock_t lock;
};

struct cckprng_pool_ctx {
    uint8_t data[CCKPRNG_POOL_NBYTES];
};

struct cckprng_sched_ctx {
    uint64_t reseed_sched;
    uint64_t reseed_last;
    uint32_t pool_idx;
};

struct cckprng_ctx {
    uint8_t seed[CCKPRNG_SEED_NBYTES];
    struct cckprng_sched_ctx sched;
    cc_lock_t lock;
    struct cckprng_gen_ctx *gens;
    struct cckprng_pool_ctx pools[CCKPRNG_NPOOLS];
    struct cckprng_entropybuf entropybuf;
    struct cckprng_diag diag;
#if CCKPRNG_OS_USES_GETENTROPY
    cckprng_getentropy getentropy;
    void *getentropy_arg;
#endif
};

#endif

#if CCKPRNG_OS_USES_BUILTIN_FUNCTION_POINTERS
struct cckprng_funcs {
    void (*init)(struct cckprng_ctx *ctx,
                 uint32_t ngens,
                 size_t entropybuf_nbytes,
                 const void *entropybuf,
                 const uint32_t *entropybuf_nsamples,
                 size_t seed_nbytes,
                 const void *seed,
                 size_t nonce_nbytes,
                 const void *nonce);
    void (*initgen)(struct cckprng_ctx *ctx, uint32_t gen_id);
    void (*reseed)(struct cckprng_ctx *ctx, size_t nbytes, const void *seed);
    void (*refresh)(struct cckprng_ctx *ctx);
    void (*generate)(struct cckprng_ctx *ctx, uint32_t gen_idx, size_t nbytes, void *out);
#if CCKPRNG_OS_USES_GETENTROPY
    void (*init_with_getentropy)(struct cckprng_ctx *ctx,
                                 uint32_t ngens,
                                 size_t entropybuf_nbytes,
                                 const void *entropybuf,
                                 const uint32_t *entropybuf_nsamples,
                                 size_t seed_nbytes,
                                 const void *seed,
                                 size_t nonce_nbytes,
                                 const void *nonce,
                                 cckprng_getentropy getentropy,
                                 void *getentropy_arg);
#endif
};
#endif

CC_END_DECLS

#endif /* __CORECRYPTO_CCKPRNG_H__  */
