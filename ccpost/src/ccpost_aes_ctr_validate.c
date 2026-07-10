/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccpost_internal.h"
#include <corecrypto/ccaes.h>

/* Sourced from RFC 3686. Not exactly the best source, but better than nothing. */
static const uint8_t aes_128_key[] = "\xAE\x68\x52\xF8\x12\x10\x67\xCC\x4B\xF7\xA5\x76\x55\x77\xF3\x9E";
static const uint8_t aes_128_iv[] = "\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
static const uint8_t aes_128_plaintext[] = "\x53\x69\x6E\x67\x6C\x65\x20\x62\x6C\x6F\x63\x6B\x20\x6D\x73\x67";
static const uint8_t aes_128_ciphertext[] = "\xE4\x09\x5D\x4F\xB7\xA7\xB3\x79\x2D\x61\x75\xA3\x26\x13\x11\xB8";

static const uint8_t aes_192_key[] = "\x16\xAF\x5B\x14\x5F\xC9\xF5\x79\xC1\x75\xF9\x3E\x3B\xFB\x0E\xED\x86\x3D\x06\xCC\xFD\xB7\x85\x15";
static const uint8_t aes_192_iv[] = "\x00\x00\x00\x48\x36\x73\x3C\x14\x7D\x6D\x93\xCB\x00\x00\x00\x01";
static const uint8_t aes_192_plaintext[] = "\x53\x69\x6E\x67\x6C\x65\x20\x62\x6C\x6F\x63\x6B\x20\x6D\x73\x67";
static const uint8_t aes_192_ciphertext[] = "\x4B\x55\x38\x4F\xE2\x59\xC9\xC8\x4E\x79\x35\xA0\x03\xCB\xE9\x28";

static const uint8_t aes_256_key[] = "\x77\x6B\xEF\xF2\x85\x1D\xB0\x6F\x4C\x8A\x05\x42\xC8\x69\x6F\x6C\x6A\x81\xAF\x1E\xEC\x96\xB4\xD3\x7F\xC1\xD6\x89\xE6\xC1\xC1\x04";
static const uint8_t aes_256_iv[] = "\x00\x00\x00\x60\xDB\x56\x72\xC9\x7A\xA8\xF0\xB2\x00\x00\x00\x01";
static const uint8_t aes_256_plaintext[] = "\x53\x69\x6E\x67\x6C\x65\x20\x62\x6C\x6F\x63\x6B\x20\x6D\x73\x67";
static const uint8_t aes_256_ciphertext[] = "\x14\x5A\xD0\x1D\xBF\x82\x4E\xC7\x56\x08\x63\xDC\x71\xE3\xE0\xC0";

cc_error_t ccpost_aes_ctr_validate_encrypt(void)
{
    uint8_t output[16];

    /* Run AES-128 validation */
    cc_post_func_log("AES-128 encrypt validation");
    if (ccctr_one_shot(ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_128, aes_128_key, aes_128_iv, CCAES_BLOCK_SIZE, aes_128_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_128_ciphertext, output) != 0) {
        cc_post_func_hex_log("output", CCAES_BLOCK_SIZE, output);
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-192 encrypt validation");
    if (ccctr_one_shot(ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_192, aes_192_key, aes_192_iv, CCAES_BLOCK_SIZE, aes_192_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_192_ciphertext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-256 encrypt validation");
    if (ccctr_one_shot(ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_256, aes_256_key, aes_256_iv, CCAES_BLOCK_SIZE, aes_256_plaintext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_256_ciphertext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    return CCERR_OK;
}


cc_error_t ccpost_aes_ctr_validate_decrypt(void)
{
    uint8_t output[16];

    /* Run AES-128 validation */
    cc_post_func_log("AES-128 decrypt validation");
    if (ccctr_one_shot(ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_128, aes_128_key, aes_128_iv, CCAES_BLOCK_SIZE, aes_128_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_128_plaintext, output) != 0) {
        cc_post_func_hex_log("output", CCAES_BLOCK_SIZE, output);
        return CCERR_INTEGRITY;
    }

    /* Run AES-192 validation */
    cc_post_func_log("AES-192 decrypt validation");
    if (ccctr_one_shot(ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_192, aes_192_key, aes_192_iv, CCAES_BLOCK_SIZE, aes_192_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_192_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    /* Run AES-256 validation */
    cc_post_func_log("AES-256 decrypt validation");
    if (ccctr_one_shot(ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_256, aes_256_key, aes_256_iv, CCAES_BLOCK_SIZE, aes_256_ciphertext, output) != CCERR_OK) {
        return CCERR_INTEGRITY;
    }

    if (cc_cmp_safe(CCAES_BLOCK_SIZE, aes_256_plaintext, output) != 0) {
        return CCERR_INTEGRITY;
    }

    return CCERR_OK;
}

/* Is it really necessary to validate it both ways? We use the same underlying ecb encryption mode. */
cc_error_t ccpost_aes_ctr_validate(void)
{
    cc_error_t res = CCERR_OK;

    res |= ccpost_aes_ctr_validate_encrypt();
    res |= ccpost_aes_ctr_validate_decrypt();

    return res;
}
