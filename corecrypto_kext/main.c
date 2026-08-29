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
