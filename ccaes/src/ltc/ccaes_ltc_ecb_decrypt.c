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

cc_error_t ccaes_ltc_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const ccecb_ctx *skey)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    const uint32_t *rk;
    int Nr, r;
    const ltc_rijndael_keysched *rijndael;

    rijndael = (const ltc_rijndael_keysched *)skey;

    Nr = rijndael->Nr;
    rk = rijndael->dK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    cc_load32_be(s0, ct      ); s0 ^= rk[0];
    cc_load32_be(s1, ct  +  4); s1 ^= rk[1];
    cc_load32_be(s2, ct  +  8); s2 ^= rk[2];
    cc_load32_be(s3, ct  + 12); s3 ^= rk[3];

#if CC_SMALL_CODE
    for (r = 0; ; r++) {
        rk += 4;
        t0 =
        Td0(cc_byte(s0, 3)) ^
        Td1(cc_byte(s3, 2)) ^
        Td2(cc_byte(s2, 1)) ^
        Td3(cc_byte(s1, 0)) ^
        rk[0];
        t1 =
        Td0(cc_byte(s1, 3)) ^
        Td1(cc_byte(s0, 2)) ^
        Td2(cc_byte(s3, 1)) ^
        Td3(cc_byte(s2, 0)) ^
        rk[1];
        t2 =
        Td0(cc_byte(s2, 3)) ^
        Td1(cc_byte(s1, 2)) ^
        Td2(cc_byte(s0, 1)) ^
        Td3(cc_byte(s3, 0)) ^
        rk[2];
        t3 =
        Td0(cc_byte(s3, 3)) ^
        Td1(cc_byte(s2, 2)) ^
        Td2(cc_byte(s1, 1)) ^
        Td3(cc_byte(s0, 0)) ^
        rk[3];
        if (r == Nr-2) {
            break;
        }
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;

#else

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {

        t0 =
        Td0(cc_byte(s0, 3)) ^
        Td1(cc_byte(s3, 2)) ^
        Td2(cc_byte(s2, 1)) ^
        Td3(cc_byte(s1, 0)) ^
        rk[4];
        t1 =
        Td0(cc_byte(s1, 3)) ^
        Td1(cc_byte(s0, 2)) ^
        Td2(cc_byte(s3, 1)) ^
        Td3(cc_byte(s2, 0)) ^
        rk[5];
        t2 =
        Td0(cc_byte(s2, 3)) ^
        Td1(cc_byte(s1, 2)) ^
        Td2(cc_byte(s0, 1)) ^
        Td3(cc_byte(s3, 0)) ^
        rk[6];
        t3 =
        Td0(cc_byte(s3, 3)) ^
        Td1(cc_byte(s2, 2)) ^
        Td2(cc_byte(s1, 1)) ^
        Td3(cc_byte(s0, 0)) ^
        rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }


        s0 =
        Td0(cc_byte(t0, 3)) ^
        Td1(cc_byte(t3, 2)) ^
        Td2(cc_byte(t2, 1)) ^
        Td3(cc_byte(t1, 0)) ^
        rk[0];
        s1 =
        Td0(cc_byte(t1, 3)) ^
        Td1(cc_byte(t0, 2)) ^
        Td2(cc_byte(t3, 1)) ^
        Td3(cc_byte(t2, 0)) ^
        rk[1];
        s2 =
        Td0(cc_byte(t2, 3)) ^
        Td1(cc_byte(t1, 2)) ^
        Td2(cc_byte(t0, 1)) ^
        Td3(cc_byte(t3, 0)) ^
        rk[2];
        s3 =
        Td0(cc_byte(t3, 3)) ^
        Td1(cc_byte(t2, 2)) ^
        Td2(cc_byte(t1, 1)) ^
        Td3(cc_byte(t0, 0)) ^
        rk[3];
    }
#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
    (Td4[cc_byte(t0, 3)] & 0xff000000) ^
    (Td4[cc_byte(t3, 2)] & 0x00ff0000) ^
    (Td4[cc_byte(t2, 1)] & 0x0000ff00) ^
    (Td4[cc_byte(t1, 0)] & 0x000000ff) ^
    rk[0];
    cc_store32_be(s0, pt);
    s1 =
    (Td4[cc_byte(t1, 3)] & 0xff000000) ^
    (Td4[cc_byte(t0, 2)] & 0x00ff0000) ^
    (Td4[cc_byte(t3, 1)] & 0x0000ff00) ^
    (Td4[cc_byte(t2, 0)] & 0x000000ff) ^
    rk[1];
    cc_store32_be(s1, pt+4);
    s2 =
    (Td4[cc_byte(t2, 3)] & 0xff000000) ^
    (Td4[cc_byte(t1, 2)] & 0x00ff0000) ^
    (Td4[cc_byte(t0, 1)] & 0x0000ff00) ^
    (Td4[cc_byte(t3, 0)] & 0x000000ff) ^
    rk[2];
    cc_store32_be(s2, pt+8);
    s3 =
    (Td4[cc_byte(t3, 3)] & 0xff000000) ^
    (Td4[cc_byte(t2, 2)] & 0x00ff0000) ^
    (Td4[cc_byte(t1, 1)] & 0x0000ff00) ^
    (Td4[cc_byte(t0, 0)] & 0x000000ff) ^
    rk[3];
    cc_store32_be(s3, pt+12);

    return CCERR_OK;
}

int ccaes_ecb_decrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    cc_error_t err = CCERR_OK;
    const uint8_t *_ct = in;
    uint8_t *_pt = out;

    cc_debug_client_abort((out == NULL || in == NULL), "ccaes_ecb_decrypt: null pointer alert", CCERR_PARAMETER);

    while (nblocks--) {
        ccaes_ltc_ecb_decrypt(_ct, _pt, ctx);
        _ct += CCAES_BLOCK_SIZE;
        _pt += CCAES_BLOCK_SIZE;
    }

    return err;
}

const struct ccmode_ecb ccaes_ltc_ecb_decrypt_mode = {
    .size = ccn_sizeof_size(sizeof(ltc_rijndael_keysched)),
    .block_size = CCAES_BLOCK_SIZE,
    .init = &ccaes_ecb_decrypt_init,
    .ecb = &ccaes_ecb_decrypt,

    .impl_name = "ltc",
};
