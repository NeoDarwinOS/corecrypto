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
#include "corecrypto/ccdrbg_df.h"
#include <corecrypto/ccdrbg.h>

/*
 [AES-256 no df]
[PredictionResistance = False]
[EntropyInputLen = 384]
[NonceLen = 0]
[PersonalizationStringLen = 384]
[AdditionalInputLen = 384]
[ReturnedBitsLen = 512]

COUNT = 0
EntropyInput = 9c2aa30349a0253b3a97ccf924f8bcafe1e1364600b4905a4d9a0d54f7f56ebd00079fcc12f83dfac71aa1f2c847127e
Nonce = 
PersonalizationString = 57164cea958223964e94b3596c1afc06818dfe90841132c327342bbb654b74f20e5f50658324061205a8eea21dddcf48
** INSTANTIATE:
	Key = 983365121b673014dd60cb518c293322aecb88ebc9c5c9f76de0e33c284d8757
	V   = 7c38cc63a67a119c1310badea09ce8b8

AdditionalInput = 4125bec3174314c603cf052af47bebf6433a17cd8a8fcb186f14cbd5761c09216d48b41d4fb17481afaf4dbc08681ae9
** GENERATE (FIRST CALL):
	Key = ad7faf5506dce5599196200059d36fb0c6514fc20f422003db50b0b5ea0bb586
	V   = 4e6d99c75548c8c3944cbc2962c676c8

AdditionalInput = dabf9135ae5d14280f2e269ea83f44dc2eb4d7613e5964cb1d499f7b5bdce45402546e86a78680bcd8ce1fe9d71ee758
ReturnedBits = ec2e92976c00b2364838bd6cae8f4cc6194f39d722d88d990b32e595aa82de661534a0248de6daf4dc3698b7a0eef02dbc9e331c7cf4c029f55ca7abebd062db
** GENERATE (SECOND CALL):
	Key = e90e385e44fe64be2a457d949cc1358d0e3710767824abf959a5a88696b348a3
	V   = 9c7060edc2d40a04270c30bf86041938
 */

static const uint8_t no_df_entropy[] = "\x9c\x2a\xa3\x03\x49\xa0\x25\x3b\x3a\x97\xcc\xf9\x24\xf8\xbc\xaf\xe1\xe1\x36\x46\x00\xb4\x90\x5a\x4d\x9a\x0d\x54\xf7\xf5\x6e\xbd\x00\x07\x9f\xcc\x12\xf8\x3d\xfa\xc7\x1a\xa1\xf2\xc8\x47\x12\x7e";
static const uint8_t no_df_ps[] = "\x57\x16\x4c\xea\x95\x82\x23\x96\x4e\x94\xb3\x59\x6c\x1a\xfc\x06\x81\x8d\xfe\x90\x84\x11\x32\xc3\x27\x34\x2b\xbb\x65\x4b\x74\xf2\x0e\x5f\x50\x65\x83\x24\x06\x12\x05\xa8\xee\xa2\x1d\xdd\xcf\x48";
static const uint8_t no_df_ad1[] = "\x41\x25\xbe\xc3\x17\x43\x14\xc6\x03\xcf\x05\x2a\xf4\x7b\xeb\xf6\x43\x3a\x17\xcd\x8a\x8f\xcb\x18\x6f\x14\xcb\xd5\x76\x1c\x09\x21\x6d\x48\xb4\x1d\x4f\xb1\x74\x81\xaf\xaf\x4d\xbc\x08\x68\x1a\xe9";
static const uint8_t no_df_ad2[] = "\xda\xbf\x91\x35\xae\x5d\x14\x28\x0f\x2e\x26\x9e\xa8\x3f\x44\xdc\x2e\xb4\xd7\x61\x3e\x59\x64\xcb\x1d\x49\x9f\x7b\x5b\xdc\xe4\x54\x02\x54\x6e\x86\xa7\x86\x80\xbc\xd8\xce\x1f\xe9\xd7\x1e\xe7\x58";
static const uint8_t no_df_output[] = "\xec\x2e\x92\x97\x6c\x00\xb2\x36\x48\x38\xbd\x6c\xae\x8f\x4c\xc6\x19\x4f\x39\xd7\x22\xd8\x8d\x99\x0b\x32\xe5\x95\xaa\x82\xde\x66\x15\x34\xa0\x24\x8d\xe6\xda\xf4\xdc\x36\x98\xb7\xa0\xee\xf0\x2d\xbc\x9e\x33\x1c\x7c\xf4\xc0\x29\xf5\x5c\xa7\xab\xeb\xd0\x62\xdb";

cc_error_t ccpost_ctr_drbg_validate_no_df_no_pr(void)
{
    uint8_t state[1600];
    struct ccdrbg_info info;
    cc_error_t stat;
    uint8_t rand[64];

    struct ccdrbg_nistctr_custom custom = {
        .ctr = ccaes_ctr_crypt_mode(),
        .key_length = CCAES_KEY_SIZE_256,
        .strictFIPS = false,
        .df_ctx = NULL,
    };

    ccdrbg_factory_nistctr(&info, &custom);

    struct ccdrbg_state *drbg = (struct ccdrbg_state *)state;
    cc_clear(sizeof(state), state);

    if (sizeof(state) < info.size) {
        cc_post_func_log("state too small %zd", info.size);
        return CCERR_INTERNAL;
    }

    cc_post_func_log("state size %zd", info.size);

    cc_post_func_log("ccdrbg_init");
    stat = ccdrbg_init(&info, drbg, (sizeof(no_df_entropy)-1), no_df_entropy, 0, NULL, (sizeof(no_df_ps)-1), no_df_ps);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_init");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_generate 1");
    stat = ccdrbg_generate(&info, drbg, sizeof(rand), rand, (sizeof(no_df_ad1)-1), no_df_ad1);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_generate 1");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_generate 2");
    stat = ccdrbg_generate(&info, drbg, sizeof(rand), rand, (sizeof(no_df_ad2)-1), no_df_ad2);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_generate 1");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_done");
    ccdrbg_done(&info, drbg);

    if (cc_cmp_safe(sizeof(no_df_output)-1, rand, no_df_output) != 0) {
        cc_post_func_hex_log("output", 64, rand);
        return CCERR_INTERNAL;
    }
    
    cc_post_func_log("passed lmao.");

    return CCERR_OK;
}

/*
 [AES-256 no df]
[PredictionResistance = True]
[EntropyInputLen = 384]
[NonceLen = 0]
[PersonalizationStringLen = 384]
[AdditionalInputLen = 384]
[ReturnedBitsLen = 512]

COUNT = 0
EntropyInput = c54805274bde00aa5289e0513579019707666d2fa7a1c8908865891c87c0c652335a4d3cc415bc30742b164647f8820f
Nonce = 
PersonalizationString = d63fb5afa2101fa4b8a6c3b89d9c250ac728fc1ddad0e7585b5d54728ed20c2f940e89155596e3b963635b6d6088164b
** INSTANTIATE:
	Key = 40783a732e8b29b7434c97186c2e57160ee9d10f301144a6d47618bdb3e15765
	V   = d534c7e3a62575fdc6eab8a55276a1ca

AdditionalInput = 744bfae3c23a5cc9a3b373b6c50795068d35eb8a339746ac810d16f864e880061082edf9d2687c211960aa83400f85f9
EntropyInputPR = b2ad31d1f20dcf30dd526ec9156c07f270216bdb59197325bab180675929888ab699c54fb21819b7d921d6346bff2f7f
** GENERATE (FIRST CALL):
	Key = 8664ee28c40e116e72a43ae037b313d563a5dd87ff2eac6ba3c6bd47519f28d2
	V   = 711df85543236d310ead4d7bfba52958

AdditionalInput = ad55c682962aa4fe9ebc227c9402e79b0aa7874844d33eaee7e2d15baf81d9d33936e4d93f28ad109657b512aee115a5
EntropyInputPR = eca449048d26fd38f8ca435237dce66eadec7069ee5dd0b70084b819a711c0820a7556bbd0ae20f06e5169278b593b71
ReturnedBits = f08fdfc1775b6feb5a4177110bf29d7c3ab715dfdc4b27200359288c0624bd5c1028acc9914d88a82b09f5eaafdc3bca8547b98481df39b86504314221cbdc3c
** GENERATE (SECOND CALL):
	Key = 5efaf8d2d42fd0fa4c299f477f9dd1614dbdefadbf48f9ea6bcee36042c459c4
	V   = fd58665119bec5bdcf29aa8986804a4f
 */
static const uint8_t no_df_pr_entropy[] = "\xc5\x48\x05\x27\x4b\xde\x00\xaa\x52\x89\xe0\x51\x35\x79\x01\x97\x07\x66\x6d\x2f\xa7\xa1\xc8\x90\x88\x65\x89\x1c\x87\xc0\xc6\x52\x33\x5a\x4d\x3c\xc4\x15\xbc\x30\x74\x2b\x16\x46\x47\xf8\x82\x0f";
static const uint8_t no_df_pr_ps[] = "\xd6\x3f\xb5\xaf\xa2\x10\x1f\xa4\xb8\xa6\xc3\xb8\x9d\x9c\x25\x0a\xc7\x28\xfc\x1d\xda\xd0\xe7\x58\x5b\x5d\x54\x72\x8e\xd2\x0c\x2f\x94\x0e\x89\x15\x55\x96\xe3\xb9\x63\x63\x5b\x6d\x60\x88\x16\x4b";
static const uint8_t no_df_pr_ad1[] = "\x74\x4b\xfa\xe3\xc2\x3a\x5c\xc9\xa3\xb3\x73\xb6\xc5\x07\x95\x06\x8d\x35\xeb\x8a\x33\x97\x46\xac\x81\x0d\x16\xf8\x64\xe8\x80\x06\x10\x82\xed\xf9\xd2\x68\x7c\x21\x19\x60\xaa\x83\x40\x0f\x85\xf9";
static const uint8_t no_df_pr_entropy1[] = "\xb2\xad\x31\xd1\xf2\x0d\xcf\x30\xdd\x52\x6e\xc9\x15\x6c\x07\xf2\x70\x21\x6b\xdb\x59\x19\x73\x25\xba\xb1\x80\x67\x59\x29\x88\x8a\xb6\x99\xc5\x4f\xb2\x18\x19\xb7\xd9\x21\xd6\x34\x6b\xff\x2f\x7f";
static const uint8_t no_df_pr_ad2[] = "\xad\x55\xc6\x82\x96\x2a\xa4\xfe\x9e\xbc\x22\x7c\x94\x02\xe7\x9b\x0a\xa7\x87\x48\x44\xd3\x3e\xae\xe7\xe2\xd1\x5b\xaf\x81\xd9\xd3\x39\x36\xe4\xd9\x3f\x28\xad\x10\x96\x57\xb5\x12\xae\xe1\x15\xa5";
static const uint8_t no_df_pr_entropy2[] = "\xec\xa4\x49\x04\x8d\x26\xfd\x38\xf8\xca\x43\x52\x37\xdc\xe6\x6e\xad\xec\x70\x69\xee\x5d\xd0\xb7\x00\x84\xb8\x19\xa7\x11\xc0\x82\x0a\x75\x56\xbb\xd0\xae\x20\xf0\x6e\x51\x69\x27\x8b\x59\x3b\x71";
static const uint8_t no_df_pr_output[] = "\xf0\x8f\xdf\xc1\x77\x5b\x6f\xeb\x5a\x41\x77\x11\x0b\xf2\x9d\x7c\x3a\xb7\x15\xdf\xdc\x4b\x27\x20\x03\x59\x28\x8c\x06\x24\xbd\x5c\x10\x28\xac\xc9\x91\x4d\x88\xa8\x2b\x09\xf5\xea\xaf\xdc\x3b\xca\x85\x47\xb9\x84\x81\xdf\x39\xb8\x65\x04\x31\x42\x21\xcb\xdc\x3c";

cc_error_t ccpost_ctr_drbg_validate_no_df_pr(void)
{
    ccdrbg_status_t stat;
    struct ccdrbg_info info;
    uint8_t rand[64];

    struct ccdrbg_nistctr_custom custom = {
        .ctr = ccaes_ctr_crypt_mode(),
        .key_length = CCAES_KEY_SIZE_256,
        .strictFIPS = false,
        .df_ctx = NULL,
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
    stat = ccdrbg_init(&info, drbg, (sizeof(no_df_pr_entropy)-1), no_df_pr_entropy, 0, NULL, (sizeof(no_df_pr_ps)-1), no_df_pr_ps);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_init");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_reseed 1");
    stat = ccdrbg_reseed(&info, drbg, (sizeof(no_df_pr_entropy1)-1), no_df_pr_entropy1, (sizeof(no_df_pr_ad1)-1), no_df_pr_ad1);
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
    stat = ccdrbg_reseed(&info, drbg, (sizeof(no_df_pr_entropy2)-1), no_df_pr_entropy2, (sizeof(no_df_pr_ad2)-1), no_df_pr_ad2);
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

    if (cc_cmp_safe(sizeof(no_df_pr_output)-1, rand, no_df_pr_output) != 0) {
        cc_post_func_hex_log("output", 64, rand);
        return CCERR_INTERNAL;
    }
    
    cc_post_func_log("passed lmao.");
    
    return CCERR_OK;
}

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

static const uint8_t df_pr_entropy[] = "\x53\x43\x46\xa3\xe0\xba\xa6\x5d\x7a\x51\x87\x1b\x6d\x63\x3a\x6f\x1e\xfa\x9f\xf5\x5d\xfd\xe3\x21\x2c\x95\x02\x9a\xdf\x23\x87\xd9";
static const uint8_t df_pr_nonce[] = "\x0c\xbe\x99\x82\x15\x09\x97\x5d\x82\x4f\xd8\x26\xc4\x7d\x2a\xbc";
static const uint8_t df_pr_ps[] = "\x02\x0d\x73\x40\x56\x9e\x68\xd9\x92\xe6\xe8\xdd\xfb\xea\xd9\xf9\x93\xc7\x4d\x97\x1e\x43\x39\xfe\x91\x07\x4f\x87\xe9\xd7\xd7\x77";
static const uint8_t df_pr_ad1[] = "\xf4\x10\x40\xef\xf2\xa7\x01\x02\x87\xc2\xa7\x6d\x78\x67\xa6\x6e\x61\x29\x9b\xe1\xe1\x24\x7a\x6b\x22\xa6\x4b\x82\x9a\xda\x86\x24";
static const uint8_t df_pr_entropy1[] = "\x28\x60\x91\x70\x9d\x2e\x91\xbf\xef\x66\x54\xb8\x44\x9d\x5e\x55\x64\xb6\xc2\xfe\x1f\x3e\x4e\x6e\x59\xfe\x77\x64\x61\xbf\xb0\xdc";
static const uint8_t df_pr_ad2[] = "\x94\xef\xe6\x8e\x21\x85\x64\x6a\x17\xbb\x8a\x83\x26\x81\x42\xa7\xb7\xa0\x27\x86\xc1\xee\x90\xab\x8f\x73\x99\xcc\xf5\x43\xde\x26";
static const uint8_t df_pr_entropy2[] = "\xe6\x8e\x12\x7b\x2e\x5b\x9d\x65\x39\xc2\x6f\x7e\x78\xbe\xc1\x33\x14\xe3\x7f\xeb\xdb\x71\x05\xd1\xd6\x5f\x0b\xde\x23\xc8\x7d\x38";
static const uint8_t df_pr_output[] = "\xda\x63\x89\xd1\x51\xe3\xb2\xb3\x32\xfb\xcc\x02\xb2\xcc\x5a\xf4\xf6\x98\x35\xe9\xfb\xbe\x19\x13\x0f\x91\xcb\xf3\x0a\x3c\x24\x58\x0e\xbf\xb4\x31\x1b\x34\x87\xe9\xd6\xa6\x1d\xe9\xdc\x28\x42\xc1\x07\x15\x21\x58\xb0\xe7\x5a\x93\x2c\x38\xe5\xb8\xdd\xff\x10\xe6";

cc_error_t ccpost_ctr_drbg_validate_df_pr(void)
{
    ccdrbg_df_bc_ctx_t df;
    ccdrbg_status_t stat;
    struct ccdrbg_info info;
    uint8_t rand[64];

    ccdrbg_df_bc_init(&df, ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_256);

    struct ccdrbg_nistctr_custom custom = {
        .ctr = ccaes_ctr_crypt_mode(),
        .key_length = CCAES_KEY_SIZE_256,
        .strictFIPS = false,
        .df_ctx = (ccdrbg_df_ctx_t *)&df,
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
    stat = ccdrbg_init(&info, drbg, (sizeof(df_pr_entropy)-1), df_pr_entropy, (sizeof(df_pr_nonce)-1), df_pr_nonce, (sizeof(df_pr_ps)-1), df_pr_ps);
    if (stat != CCDRBG_STATUS_OK) {
        cc_post_func_log("failed ccdrbg_init");
        return CCERR_INTERNAL;
    }

    cc_post_func_log("ccdrbg_reseed 1");
    stat = ccdrbg_reseed(&info, drbg, (sizeof(df_pr_entropy1)-1), df_pr_entropy1, (sizeof(df_pr_ad1)-1), df_pr_ad1);
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
    stat = ccdrbg_reseed(&info, drbg, (sizeof(df_pr_entropy2)-1), df_pr_entropy2, (sizeof(df_pr_ad2)-1), df_pr_ad2);
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

    if (cc_cmp_safe(sizeof(df_pr_output)-1, rand, df_pr_output) != 0) {
        cc_post_func_hex_log("output", 64, rand);
        return CCERR_INTERNAL;
    }

    return CCERR_OK;
}

cc_error_t ccpost_ctr_drbg_validate(void)
{
    cc_error_t err = 0;

    err |= ccpost_ctr_drbg_validate_no_df_no_pr();
    err |= ccpost_ctr_drbg_validate_no_df_pr();
    err |= ccpost_ctr_drbg_validate_df_pr();

    return err;
}
