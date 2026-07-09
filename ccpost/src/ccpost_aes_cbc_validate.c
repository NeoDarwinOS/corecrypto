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
static const uint8_t aes_128_key[] = "\x1f\x8e\x49\x73\x95\x3f\x3f\xb0\xbd\x6b\x16\x66\x2e\x9a\x3c\x17";
static const uint8_t aes_128_iv[] = "\x2f\xe2\xb3\x33\xce\xda\x8f\x98\xf4\xa9\x9b\x40\xd2\xcd\x34\xa8";
static const uint8_t aes_128_plaintext[] = "\x45\xcf\x12\x96\x4f\xc8\x24\xab\x76\x61\x6a\xe2\xf4\xbf\x08\x22";
static const uint8_t aes_128_ciphertext[] = "\x0f\x61\xc4\xd4\x4c\x51\x47\xc0\x3c\x19\x5a\xd\x7e\x2c\xc1\x2\xb2";

static const uint8_t aes_192_key[] = "\xba\x75\xf4\xd1\xd9\xd7\xcf\x7f\x55\x14\x45\xd5\x6c\xc1\xa8\xab\x2a\x07\x8e\x15\xe0\x49\xdc\x2c";
static const uint8_t aes_192_iv[] = "\x53\x1c\xe7\x81\x76\x40\x16\x66\xaa\x30\xdb\x94\xec\x4a\x30\xeb";
static uint8_t aes_192_plaintext[] = "\xc5\x1f\xc2\x76\x77\x4d\xad\x94\xbc\xdc\x1d\x28\x91\xec\x86\x68";
static uint8_t aes_192_ciphertext[] = "\x70\xdd\x95\xa1\x4e\xe9\x75\xe2\x39\xdf\x36\xff\x4a\xee\x1d\x5d";

static uint8_t aes_256_key[] = "\x6e\xd7\x6d\x2d\x97\xc6\x9f\xd1\x33\x95\x89\x52\x39\x31\xf2\xa6\xcf\xf5\x54\xb1\x5f\x73\x8f\x21\xec\x72\xdd\x97\xa7\x33\x09\x07";
static uint8_t aes_256_iv[] = "\x85\x1e\x87\x64\x77\x6e\x67\x96\xaa\xb7\x22\xdb\xb6\x44\xac\xe8";
static uint8_t aes_256_plaintext[] = "\x62\x82\xb8\xc0\x5c\x5c\x15\x30\xb9\x7d\x48\x16\xca\x43\x47\x62";
static uint8_t aes_256_ciphertext[] = "\x6a\xcc\x04\x14\x2e\x10\x0a\x65\xf5\x1b\x97\xad\xf5\x17\x2c\x41";

cc_error_t ccpost_aes_cbc_validate_encrypt(void)
{
    uint8_t output[16];

    /* Run AES-128 validation */
    cc_post_func_log("AES-128 encrypt validation enter");
    if (cccbc_one_shot(ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_128, aes_128_key, 1, aes_128_iv, aes_128_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_128_ciphertext, output) != 0) {
        cc_post_func_hex_log("output", CCAES_BLOCK_SIZE, (&output[0]));
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-192 encrypt validation enter");
    if (cccbc_one_shot(ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_192, aes_192_key, 1, aes_192_iv, aes_192_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_192_ciphertext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-256 encrypt validation enter");
    if (cccbc_one_shot(ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_256, aes_256_key, 1, aes_256_iv, aes_256_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_256_ciphertext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    return CCERR_OK;
}


cc_error_t ccpost_aes_cbc_validate_decrypt(void)
{
    uint8_t output[16];

    /* Run AES-128 validation */
    cc_post_func_log("AES-128 decrypt validation enter");
    if (cccbc_one_shot(ccaes_cbc_decrypt_mode(), 16, aes_128_key, 1, aes_128_iv, aes_128_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_128_plaintext, output) != 0) {
        cc_post_func_hex_log("output", CCAES_BLOCK_SIZE, output);
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-192 decrypt validation enter");
    if (cccbc_one_shot(ccaes_cbc_decrypt_mode(), CCAES_KEY_SIZE_192, aes_192_key, 1, aes_192_iv, aes_192_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_192_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-256 validation */
    cc_post_func_log("AES-256 decrypt validation enter");
    if (cccbc_one_shot(ccaes_cbc_decrypt_mode(), CCAES_KEY_SIZE_256, aes_256_key, 1, aes_256_iv, aes_256_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_256_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    return CCERR_OK;
}

cc_error_t ccpost_aes_cbc_validate(void)
{
    cc_error_t res = CCERR_OK;

    res |= ccpost_aes_cbc_validate_encrypt();
    res |= ccpost_aes_cbc_validate_decrypt();

    return res;
}
