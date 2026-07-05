/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto_kext_if.h"

static struct crypto_functions corecrypto_registration_if;

kern_return_t corecrypto_start(kmod_info_t * ki, void *d);
kern_return_t corecrypto_stop(kmod_info_t *ki, void *d);

void cc_kernel_populate_registration(void)
{
    corecrypto_registration_if.ccdigest_init_fn = &ccdigest_init;
    corecrypto_registration_if.ccdigest_update_fn = &ccdigest_update;
    corecrypto_registration_if.ccdigest_final_fn = &ccdigest_final;
    corecrypto_registration_if.ccdigest_fn = &ccdigest;

    /* MISSING COMPONENTS: ccmd5, ccsha256, ccsha384, ccsha512 */
    corecrypto_registration_if.ccsha1_di = ccsha1_di();
    
    corecrypto_registration_if.cchmac_init_fn = &cchmac_init;
    corecrypto_registration_if.cchmac_update_fn = &cchmac_update;
    corecrypto_registration_if.cchmac_final_fn = &cchmac_final;
    corecrypto_registration_if.cchmac_fn = &cchmac;
    
    /* MISSING COMPONENTS: ccaes in ctr, xts and gcm */
    corecrypto_registration_if.ccaes_ecb_encrypt = ccaes_ecb_encrypt_mode();
    corecrypto_registration_if.ccaes_ecb_decrypt = ccaes_ecb_decrypt_mode();
    corecrypto_registration_if.ccaes_cbc_encrypt = ccaes_cbc_encrypt_mode();
    corecrypto_registration_if.ccaes_cbc_decrypt = ccaes_cbc_encrypt_mode();
    
    /* MISSING COMPONENTS: ccgcm_[init_with_iv, inc_iv ]  */
    
    
    /* MISSING COMPONENTS: ccchacha20poly1305_[all]  */
    
    
    /* MISSING COMPONENTS: ccdes_[ecb, cbc]_[encrypt, decrypt]  */
    
    
    /* MISSING COMPONENTS: cctdes_[ecb, cbc]_[encrypt, decrypt]  */
    
    
    /* MISSING COMPONENTS: ccrc4_info  */
    
    
    /* MISSING COMPONENTS: cc[blowfish, cast]_ecb_[encrypt, decrypt]  */
    
    
    /* MISSING COMPONENTS: ccdes_key_[is_weak, set_odd_parity]  */
    
    
    /* MISSING COMPONETNS: ccpad_[cts3, xts]_[encrypt, decrypt] */
    
    
    /* MISSING COMPONENTS: ccrng */
    
    
    /* MISSING COMPONENTS: ccrsa_[make_pub, verify_pkcs1v15] */
}

kern_return_t corecrypto_start(kmod_info_t * ki, void *d)
{
    cc_debug_log("kmod has been loaded, hello! :)");
    
    cc_kernel_populate_registration();
    
    kern_return_t res = register_crypto_functions(&corecrypto_registration_if);
    if (res != KERN_SUCCESS) {
        cc_internal_crash(1, "well. this is awkward.");
    }
    
    return KERN_SUCCESS;
}

kern_return_t corecrypto_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
