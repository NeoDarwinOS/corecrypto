/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "ccpost_internal.h"
#include "corecrypto/cc.h"
#include "corecrypto/cc_error.h"
#include "corecrypto/ccaes.h"
#include <corecrypto/ccdrbg.h>

/*
 [AES-256 use df]
 [PredictionResistance = True]
 [EntropyInputLen = 256]
 [NonceLen = 128]
 [PersonalizationStringLen = 256]
 [AdditionalInputLen = 256]
 [ReturnedBitsLen = 512]

 COUNT = 0
 EntropyInput = 534346a3e0baa65d7a51871b6d633a6f1efa9ff55dfde3212c95029adf2387d9
 Nonce = 0cbe99821509975d824fd826c47d2abc
 PersonalizationString = 020d7340569e68d992e6e8ddfbead9f993c74d971e4339fe91074f87e9d7d777
 AdditionalInput = f41040eff2a7010287c2a76d7867a66e61299be1e1247a6b22a64b829ada8624
 EntropyInputPR = 286091709d2e91bfef6654b8449d5e5564b6c2fe1f3e4e6e59fe776461bfb0dc
 AdditionalInput = 94efe68e2185646a17bb8a83268142a7b7a02786c1ee90ab8f7399ccf543de26
 EntropyInputPR = e68e127b2e5b9d6539c26f7e78bec13314e37febdb7105d1d65f0bde23c87d38
 ReturnedBits = da6389d151e3b2b332fbcc02b2cc5af4f69835e9fbbe19130f91cbf30a3c24580ebfb4311b3487e9d6a61de9dc2842c107152158b0e75a932c38e5b8ddff10e6
 */

static const uint8_t entropy[] = "\x53\x43\x46\xa3\xe0\xba\xa6\x5d\x7a\x51\x87\x1b\x6d\x63\x3a\x6f\x1e\xfa\x9f\xf5\x5d\xfd\xe3\x21\x2c\x95\x02\x9a\xdf\x23\x87\xd9";
static const uint8_t nonce[] = "\x0c\xbe\x99\x82\x15\x09\x97\x5d\x82\x4f\xd8\x26\xc4\x7d\x2a\xbc";
static const uint8_t ps[] = "\x02\x0d\x73\x40\x56\x9e\x68\xd9\x92\xe6\xe8\xdd\xfb\xea\xd9\xf9\x93\xc7\x4d\x97\x1e\x43\x39\xfe\x91\x07\x4f\x87\xe9\xd7\xd7\x77";
static const uint8_t ad1[] = "\xf4\x10\x40\xef\xf2\xa7\x01\x02\x87\xc2\xa7\x6d\x78\x67\xa6\x6e\x61\x29\x9b\xe1\xe1\x24\x7a\x6b\x22\xa6\x4b\x82\x9a\xda\x86\x24";
static const uint8_t entropy1[] = "\x28\x60\x91\x70\x9d\x2e\x91\xbf\xef\x66\x54\xb8\x44\x9d\x5e\x55\x64\xb6\xc2\xfe\x1f\x3e\x4e\x6e\x59\xfe\x77\x64\x61\xbf\xb0\xdc";
static const uint8_t ad2[] = "\x94\xef\xe6\x8e\x21\x85\x64\x6a\x17\xbb\x8a\x83\x26\x81\x42\xa7\xb7\xa0\x27\x86\xc1\xee\x90\xab\x8f\x73\x99\xcc\xf5\x43\xde\x26";
static const uint8_t entropy2[] = "\xe6\x8e\x12\x7b\x2e\x5b\x9d\x65\x39\xc2\x6f\x7e\x78\xbe\xc1\x33\x14\xe3\x7f\xeb\xdb\x71\x05\xd1\xd6\x5f\x0b\xde\x23\xc8\x7d\x38";
static const uint8_t output[] = "\xda\x63\x89\xd1\x51\xe3\xb2\xb3\x32\xfb\xcc\x02\xb2\xcc\x5a\xf4\xf6\x98\x35\xe9\xfb\xbe\x19\x13\x0f\x91\xcb\xf3\x0a\x3c\x24\x58\x0e\xbf\xb4\x31\x1b\x34\x87\xe9\xd6\xa6\x1d\xe9\xdc\x28\x42\xc1\x07\x15\x21\x58\xb0\xe7\x5a\x93\x2c\x38\xe5\xb8\xdd\xff\x10\xe6";

cc_error_t ccpost_ctr_drbg_validate(void)
{
    ccdrbg_status_t stat;
    struct ccdrbg_info info;
    uint8_t rand[64];

    struct ccdrbg_nistctr_custom custom = {
        .ctr = ccaes_ctr_crypt_mode(),
        .key_length = 32,
        .strictFIPS = false,
        .use_df = true,
    };

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[1600];
    struct ccdrbg_state *drbg = (struct ccdrbg_state *)state;
    cc_clear(sizeof(state), state);

    if (sizeof(state) < info.size) {
        cc_post_func_log("state too small %zd", info.size);
        return CCERR_INTERNAL;
    }

    cc_post_func_log("state size %zd", info.size);

    cc_post_func_log("ccdrbg_init");
    stat = ccdrbg_init(&info, drbg, (sizeof(entropy)-1), entropy, (sizeof(nonce)-1), nonce, (sizeof(ps)-1), ps);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_init");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_reseed 1");
    stat = ccdrbg_reseed(&info, drbg, (sizeof(entropy1)-1), entropy1, (sizeof(ad1)-1), ad1);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_reseed 1");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_generate 1");
    stat = ccdrbg_generate(&info, drbg, sizeof(rand), rand, 0, NULL);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_generate 1");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_reseed 2");
    stat = ccdrbg_reseed(&info, drbg, (sizeof(entropy2)-1), entropy2, (sizeof(ad2)-1), ad2);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_reseed 1");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_generate 2");
    stat = ccdrbg_generate(&info, drbg, sizeof(rand), rand, 0, NULL);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_generate 1");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_done");
    ccdrbg_done(&info, drbg);

    if (cc_cmp_safe(64, rand, output) != 0) {
        cc_post_func_hex_log("output", 64, rand);
        return CCERR_INTERNAL;
    }

    return CCERR_OK;
}
