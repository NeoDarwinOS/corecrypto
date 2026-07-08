/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccpost_internal.h"
#include <corecrypto/ccaes.h>

/* The vectors found here were sourced from the NIST's AES MMT. If anyone has better vectors, let me know. */
static uint8_t aes_128_key[] = "\xed\xfd\xb2\x57\xcb\x37\xcd\xf1\x82\xc5\x45\x5b\x0c\x0e\xfe\xbb";
static uint8_t aes_128_plaintext[] = "\x16\x95\xfe\x47\x54\x21\xca\xce\x35\x57\xda\xca\x01\xf4\x45\xff";
static uint8_t aes_128_ciphertext[] = "\x78\x88\xbe\xae\x6e\x7a\x42\x63\x32\xa7\xea\xa2\xf8\x08\xe6\x37";

static uint8_t aes_192_key[] = "\x61\x39\x6c\x53\x0c\xc1\x74\x9a\x5b\xab\x6f\xbc\xf9\x06\xfe\x67\x2d\x0c\x4a\xb2\x01\xaf\x45\x54";
static uint8_t aes_192_plaintext[] = "\x60\xbc\xdb\x94\x16\xba\xc0\x8d\x7f\xd0\xd7\x80\x35\x37\x40\xa5";
static uint8_t aes_192_ciphertext[] = "\x24\xf4\x0c\x4e\xec\xd9\xc4\x98\x25\x00\x0f\xcb\x49\x72\x64\x7a";

static uint8_t aes_256_key[] = "\xcc\x22\xda\x78\x7f\x37\x57\x11\xc7\x63\x02\xbe\xf0\x97\x9d\x8e\xdd\xf8\x42\x82\x9c\x2b\x99\xef\x3d\xd0\x4e\x23\xe5\x4c\xc2\x4b";
static uint8_t aes_256_plaintext[] = "\xcc\xc6\x2c\x6b\x0a\x09\xa6\x71\xd6\x44\x56\x81\x8d\xb2\x9a\x4d";
static uint8_t aes_256_ciphertext[] = "\xdf\x86\x34\xca\x02\xb1\x3a\x12\x5b\x78\x6e\x1d\xce\x90\x65\x8b";

cc_error_t ccpost_aes_ecb_validate_encrypt(void)
{
    uint8_t output[16];
    cc_clear(CCAES_BLOCK_SIZE, output);

    /* Run AES-128 validation */
    cc_post_func_log("AES-128 encrypt validation enter");
    if (ccecb_one_shot(ccaes_ecb_encrypt_mode(), CCAES_KEY_SIZE_128, aes_128_key, 1, aes_128_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_128_ciphertext, output) != 0) {
        cc_post_func_hex_log("output", CCAES_BLOCK_SIZE, output);
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-192 encrypt validation enter");
    if (ccecb_one_shot(ccaes_ecb_encrypt_mode(), CCAES_KEY_SIZE_192, aes_192_key, 1, aes_192_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_192_ciphertext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-256 encrypt validation enter");
    if (ccecb_one_shot(ccaes_ecb_encrypt_mode(), CCAES_KEY_SIZE_256, aes_256_key, 1, aes_256_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_256_ciphertext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    return CCERR_OK;
}


cc_error_t ccpost_aes_ecb_validate_decrypt(void)
{
    uint8_t output[16];

    /* Run AES-128 validation */
    cc_post_func_log("AES-128 decrypt validation enter");
    if (ccecb_one_shot(ccaes_ecb_decrypt_mode(), 16, aes_128_key, 1, aes_128_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_128_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-192 decrypt validation enter");
    if (ccecb_one_shot(ccaes_ecb_decrypt_mode(), CCAES_KEY_SIZE_192, aes_192_key, 1, aes_192_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_192_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-256 validation */
    cc_post_func_log("AES-256 decrypt validation enter");
    if (ccecb_one_shot(ccaes_ecb_decrypt_mode(), CCAES_KEY_SIZE_256, aes_256_key, 1, aes_256_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_256_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    return CCERR_OK;
}

cc_error_t ccpost_aes_ecb_validate(void)
{
    cc_error_t res;

    res |= ccpost_aes_ecb_validate_encrypt();
    res |= ccpost_aes_ecb_validate_decrypt();

    return res;
}
