/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto_kext_if.h"

static struct crypto_functions corecrypto_registration_if;

kern_return_t corecrypto_start(kmod_info_t *ki, void *d);
kern_return_t corecrypto_stop(kmod_info_t *ki, void *d);

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_28_0)
//
//  [INTERNAL PROJECT TRACKING ANNOTATION]
//  Project:            corecrypto
//  Track:              Goulburn, Errinundra, Aurora, Marigold
//  Completion Status:  In Progress
//
//  Description:
//  The contract with XNU regarding SPI has changed in ways so that
//  behaviour is similar to CommonCrypto's interfaces.
//
//  We need to update based on that, and make sure that backwards compatibility
//  is not broken along the way.
//
//  Affected projects (subject to change):
//      corecrypto
//

#define CRYPTO_DIGEST_ALGS_MAX  6

static const struct ccdigest_info *crypto_digest_algs[CRYPTO_DIGEST_ALGS_MAX];

//
// For functions with a ctx_size, should we client_crash when they don't sync?
//
size_t crypto_digest_ctx_size(crypto_digest_alg_t alg) {
    return ccdigest_di_size(crypto_digest_algs[alg]);
}

void crypto_digest_init(crypto_digest_alg_t alg,
                        void *ctx,
                        size_t ctx_size) {
    cc_client_crash((ccdigest_di_size(crypto_digest_algs[alg])) != ctx_size, "ctx_size != ccdigest_di_size");
    ccdigest_init(crypto_digest_algs[alg], (ccdigest_ctx_t)ctx);
}

void crypto_digest_update(crypto_digest_alg_t alg,
                          void *ctx,
                          size_t ctx_size,
                          const void *data,
                          size_t data_size)
{
    cc_client_crash((ccdigest_di_size(crypto_digest_algs[alg])) != ctx_size, "ctx_size != ccdigest_di_size");
    ccdigest_update(crypto_digest_algs[alg], (ccdigest_ctx_t)ctx, data_size, data);
}

#define DIGEST_MAX_OUTPUT_SIZE  64

void crypto_digest_final(crypto_digest_alg_t alg,
                         void *ctx,
                         size_t ctx_size,
                         void *digest,
                         size_t digest_size) {
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];
    
    cc_client_crash((ccdigest_di_size(crypto_digest_algs[alg])) != ctx_size, "ctx_size != ccdigest_di_size");
    cc_client_crash(digest_size > crypto_digest_algs[alg]->output_size, "digest_size > output_size");
    ccdigest_final(crypto_digest_algs[alg], (ccdigest_ctx_t)ctx, buf);
    cc_copy(digest_size, digest, buf);
}

void crypto_digest(crypto_digest_alg_t alg,
                   const void *data,
                   size_t data_size,
                   void *digest,
                   size_t digest_size) {
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];

    cc_client_crash(digest_size > crypto_digest_algs[alg]->output_size, "digest_size > output_size");
    ccdigest(crypto_digest_algs[alg], data_size, data, buf);
    cc_copy(digest_size, digest, buf);
}

size_t crypto_hmac_ctx_size(crypto_digest_alg_t alg) {
    return cchmac_di_size(crypto_digest_algs[alg]);
}

void crypto_hmac_init(crypto_digest_alg_t alg,
                      void *ctx,
                      size_t ctx_size,
                      const void *key,
                      size_t key_size) {
    cc_client_crash(ctx_size != cchmac_di_size(crypto_digest_algs[alg]), "ctx_size != cchmac_di_size");
    cchmac_init(crypto_digest_algs[alg], (cchmac_ctx_t)ctx, key_size, key);
}

#endif // __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_28_0)

void cc_kernel_populate_registration(void)
{
    corecrypto_registration_if.ccdigest_init_fn = &ccdigest_init;
    corecrypto_registration_if.ccdigest_update_fn = &ccdigest_update;
    corecrypto_registration_if.ccdigest_final_fn = &ccdigest_final;
    corecrypto_registration_if.ccdigest_fn = &ccdigest;

    corecrypto_registration_if.ccmd5_di = ccmd5_di();
    corecrypto_registration_if.ccsha1_di = ccsha1_di();
    corecrypto_registration_if.ccsha256_di = ccsha256_di();
    corecrypto_registration_if.ccsha384_di = ccsha384_di();
    corecrypto_registration_if.ccsha512_di = ccsha512_di();

    corecrypto_registration_if.cchmac_init_fn = &cchmac_init;
    corecrypto_registration_if.cchmac_update_fn = &cchmac_update;
    corecrypto_registration_if.cchmac_final_fn = (cchmac_final_fn_t)&cchmac_final;
    corecrypto_registration_if.cchmac_fn = (cchmac_fn_t)&cchmac;

    /* MISSING COMPONENTS: ccaes in xts and gcm */
    corecrypto_registration_if.ccaes_ecb_encrypt = ccaes_ecb_encrypt_mode();
    corecrypto_registration_if.ccaes_ecb_decrypt = ccaes_ecb_decrypt_mode();
    corecrypto_registration_if.ccaes_cbc_encrypt = ccaes_cbc_encrypt_mode();
    corecrypto_registration_if.ccaes_cbc_decrypt = ccaes_cbc_encrypt_mode();
    corecrypto_registration_if.ccaes_ctr_crypt = ccaes_ctr_crypt_mode();

    /* MISSING COMPONENTS: ccgcm_[init_with_iv, inc_iv ]  */


    /* MISSING COMPONENTS: ccchacha20poly1305_[all]  */
    // more networking

    corecrypto_registration_if.ccdes_ecb_encrypt = ccdes_ecb_encrypt_mode();
    corecrypto_registration_if.ccdes_ecb_decrypt = ccdes_ecb_decrypt_mode();
    corecrypto_registration_if.ccdes_cbc_encrypt = ccdes_cbc_encrypt_mode();
    corecrypto_registration_if.ccdes_cbc_decrypt = ccdes_cbc_decrypt_mode();
    corecrypto_registration_if.cctdes_ecb_encrypt = ccdes3_ecb_encrypt_mode();
    corecrypto_registration_if.cctdes_ecb_decrypt = ccdes3_ecb_decrypt_mode();
    corecrypto_registration_if.cctdes_cbc_encrypt = ccdes3_cbc_encrypt_mode();
    corecrypto_registration_if.cctdes_cbc_decrypt = ccdes3_cbc_decrypt_mode();

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_10, __MAC_11_0)
    corecrypto_registration_if.ccrc4_info = ccrc4();
#endif  // __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_10, __MAC_11_0)


    /* MISSING COMPONENTS: cc[blowfish, cast]_ecb_[encrypt, decrypt]  */
#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_10, __MAC_11_0)
    
#endif

    corecrypto_registration_if.ccdes_key_is_weak_fn = (ccdes_key_is_weak_fn_t)&ccdes_key_is_weak;
    corecrypto_registration_if.ccdes_key_set_odd_parity_fn = &ccdes_key_set_odd_parity;


    /* MISSING COMPONETNS: ccpad_[cts3, xts]_[encrypt, decrypt] */

    // in xnu, netkey/key.c uses ccrng for random key fill
    //         it's also used for swap encryption and decryption
    //         remind me to write the XTS implementation for that.
    corecrypto_registration_if.ccrng_fn = &ccrng;

    /* MISSING COMPONENTS: ccrsa_[make_pub, verify_pkcs1v15] */

    // these rsa routines are used for imageboot dmg validation.
    
#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_28_0)
    crypto_digest_algs[CRYPTO_DIGEST_ALG_MD5] = ccmd5_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA1] = ccsha1_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA256] = ccsha256_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA384] = ccsha384_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA512] = ccsha512_di();
    
    corecrypto_registration_if.digest_ctx_size_fn = &crypto_digest_ctx_size;
    corecrypto_registration_if.digest_init_fn = &crypto_digest_init;
    corecrypto_registration_if.digest_update_fn = &crypto_digest_update;
    corecrypto_registration_if.digest_final_fn = &crypto_digest_final;
    corecrypto_registration_if.digest_fn = &crypto_digest;
    
    corecrypto_registration_if.hmac_ctx_size_fn = &crypto_hmac_ctx_size;
    corecrypto_registration_if.hmac_init_fn = &crypto_hmac_init;
#endif // __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_28_0)
}

//
// KPRNG
//
struct cckprng_ctx kprng_ctx;

const struct cckprng_funcs kprng_funcs = {
    cckprng_init,
    cckprng_initgen,
    cckprng_reseed,
    cckprng_refresh,
    cckprng_generate
};

// MARK: kmod entrypoints
kern_return_t corecrypto_start(kmod_info_t * ki, void *d)
{
    cc_debug_log("kmod has been loaded, hello! :)");

    if (ccpost_validate() != CCERR_OK) {
        cc_abort("The world has ended.");
    }

    cc_kernel_populate_registration();

    kern_return_t res = register_crypto_functions(&corecrypto_registration_if);
    if (res != KERN_SUCCESS) {
        cc_internal_crash(1, "well. this is awkward.");
    }
    
    // wire in kernel PRNG.
    register_and_init_prng(&kprng_ctx, &kprng_funcs);

    return KERN_SUCCESS;
}

kern_return_t corecrypto_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
