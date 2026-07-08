/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Code adapted from LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include "ccaes_ltc_internal.h"

static uint32_t setup_mix(uint32_t temp)
{
    return (Te4_3[cc_byte(temp, 2)]) ^
           (Te4_2[cc_byte(temp, 1)]) ^
           (Te4_1[cc_byte(temp, 0)]) ^
           (Te4_0[cc_byte(temp, 3)]);
}

#ifndef ENCRYPT_ONLY
#if CC_SMALL_CODE
static uint32_t setup_mix2(uint32_t temp)
{
    return Td0(255 & Te4[cc_byte(temp, 3)]) ^
           Td1(255 & Te4[cc_byte(temp, 2)]) ^
           Td2(255 & Te4[cc_byte(temp, 1)]) ^
           Td3(255 & Te4[cc_byte(temp, 0)]);
}
#endif
#endif

/**
 Initialize the AES (Rijndael) block cipher
 @param key The symmetric key you wish to pass
 @param keylen The key length in bytes
 @param num_rounds The number of rounds desired (0 for default)
 @param skey The key in as scheduled by this function.
 @return CRYPT_OK if successful
 */
static cc_error_t ccaes_ltc_init(const unsigned char *key, int keylen, int num_rounds, ltc_rijndael_keysched *skey)
{
    int i, j;
    uint32_t temp, *rk;
#ifndef ENCRYPT_ONLY
    uint32_t *rrk;
#endif

    if (keylen != 16 && keylen != 24 && keylen != 32) {
        return CCERR_PARAMETER;
    }

    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
        return CCERR_PARAMETER;
    }

    skey->Nr = 10 + ((keylen/8)-2)*2;

    /* setup the forward key */
    i                 = 0;
    rk                = skey->eK;
    cc_load32_be(rk[0], key     );
    cc_load32_be(rk[1], key +  4);
    cc_load32_be(rk[2], key +  8);
    cc_load32_be(rk[3], key + 12);
    if (keylen == 16) {
        j = 44;
        for (;;) {
            temp  = rk[3];
            rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                break;
            }
            rk += 4;
        }
    } else if (keylen == 24) {
        j = 52;
        cc_load32_be(rk[4], key + 16);
        cc_load32_be(rk[5], key + 20);
        for (;;) {
#ifdef _MSC_VER
            temp = skey->eK[rk - skey->eK + 5];
#else
            temp = rk[5];
#endif
            rk[ 6] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                break;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    } else if (keylen == 32) {
        j = 60;
        cc_load32_be(rk[4], key + 16);
        cc_load32_be(rk[5], key + 20);
        cc_load32_be(rk[6], key + 24);
        cc_load32_be(rk[7], key + 28);
        for (;;) {
#ifdef _MSC_VER
            temp = skey->eK[rk - skey->eK + 7];
#else
            temp = rk[7];
#endif
            rk[ 8] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                break;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^ setup_mix(cc_rorc(temp, 8));
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];
            rk += 8;
        }
    } else {
        /* this can't happen */
        return CCERR_INTERNAL;
    }

#ifndef ENCRYPT_ONLY
    /* setup the inverse key now */
    rk   = skey->dK;
    rrk  = skey->eK + j - 4;

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    /* copy first */
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
    rk -= 3; rrk -= 3;

    for (i = 1; i < skey->Nr; i++) {
        rrk -= 4;
        rk  += 4;
#ifdef LTC_SMALL_CODE
        temp = rrk[0];
        rk[0] = setup_mix2(temp);
        temp = rrk[1];
        rk[1] = setup_mix2(temp);
        temp = rrk[2];
        rk[2] = setup_mix2(temp);
        temp = rrk[3];
        rk[3] = setup_mix2(temp);
#else
        temp = rrk[0];
        rk[0] =
        Tks0[cc_byte(temp, 3)] ^
        Tks1[cc_byte(temp, 2)] ^
        Tks2[cc_byte(temp, 1)] ^
        Tks3[cc_byte(temp, 0)];
        temp = rrk[1];
        rk[1] =
        Tks0[cc_byte(temp, 3)] ^
        Tks1[cc_byte(temp, 2)] ^
        Tks2[cc_byte(temp, 1)] ^
        Tks3[cc_byte(temp, 0)];
        temp = rrk[2];
        rk[2] =
        Tks0[cc_byte(temp, 3)] ^
        Tks1[cc_byte(temp, 2)] ^
        Tks2[cc_byte(temp, 1)] ^
        Tks3[cc_byte(temp, 0)];
        temp = rrk[3];
        rk[3] =
        Tks0[cc_byte(temp, 3)] ^
        Tks1[cc_byte(temp, 2)] ^
        Tks2[cc_byte(temp, 1)] ^
        Tks3[cc_byte(temp, 0)];
#endif

    }

    /* copy last */
    rrk -= 4;
    rk  += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
#endif /* ENCRYPT_ONLY */

    return CCERR_OK;
}

cc_error_t ccaes_ecb_decrypt_init(const struct ccmode_ecb *ecb,
                                  ccecb_ctx *ctx,
                                  size_t key_size,
                                  const void *key)
{
    return ccaes_ltc_init(key, (int)key_size, 0, (ltc_rijndael_keysched *)ctx);
}

cc_error_t ccaes_ecb_encrypt_init(const struct ccmode_ecb *ecb,
                                  ccecb_ctx *ctx,
                                  size_t key_size,
                                  const void *key)
{
    return ccaes_ltc_init(key, (int)key_size, 0, (ltc_rijndael_keysched *)ctx);
}
