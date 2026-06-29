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

#ifndef __CORECRYPTO_CCAES_LTC_TAB_H__
#define __CORECRYPTO_CCAES_LTC_TAB_H__

#include <corecrypto/ccaes.h>

CC_PRIVATE const uint32_t TE0[256];

CC_PRIVATE const uint32_t Te4[256];

#ifndef ENCRYPT_ONLY
CC_PRIVATE const uint32_t TD0[256];
CC_PRIVATE const uint32_t Td4[256];
#endif

#if CC_SMALL_CODE

#define Te0(x) TE0[x]
#define Te1(x) RORc(TE0[x], 8)
#define Te2(x) RORc(TE0[x], 16)
#define Te3(x) RORc(TE0[x], 24)

#define Td0(x) TD0[x]
#define Td1(x) RORc(TD0[x], 8)
#define Td2(x) RORc(TD0[x], 16)
#define Td3(x) RORc(TD0[x], 24)

#define Te4_0 0x000000FF & Te4
#define Te4_1 0x0000FF00 & Te4
#define Te4_2 0x00FF0000 & Te4
#define Te4_3 0xFF000000 & Te4

#else
#define Te0(x) TE0[x]
#define Te1(x) TE1[x]
#define Te2(x) TE2[x]
#define Te3(x) TE3[x]

#define Td0(x) TD0[x]
#define Td1(x) TD1[x]
#define Td2(x) TD2[x]
#define Td3(x) TD3[x]

CC_PRIVATE const uint32_t TE1[256];
CC_PRIVATE const uint32_t TE2[256];
CC_PRIVATE const uint32_t TE3[256];

CC_PRIVATE const uint32_t Te4_0[256];
CC_PRIVATE const uint32_t Te4_1[256];
CC_PRIVATE const uint32_t Te4_2[256];
CC_PRIVATE const uint32_t Te4_3[256];

#ifndef ENCRYPT_ONLY
CC_PRIVATE const uint32_t TD1[256];
CC_PRIVATE const uint32_t TD2[256];
CC_PRIVATE const uint32_t TD3[256];

CC_PRIVATE const uint32_t Tks0[256];
CC_PRIVATE const uint32_t Tks1[256];
CC_PRIVATE const uint32_t Tks2[256];
CC_PRIVATE const uint32_t Tks3[256];
#endif

CC_PRIVATE const uint32_t rcon[];

#endif

#endif /* __CORECRYPTO_CCAES_LTC_TAB_H__ */
