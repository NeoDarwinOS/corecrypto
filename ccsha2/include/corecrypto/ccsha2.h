/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCSHA2_H__
#define __CORECRYPTO_CCSHA2_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

#define CCSHA256_BLOCK_SIZE     64
#define	CCSHA256_OUTPUT_SIZE    32
#define	CCSHA256_STATE_SIZE     32

CC_EXPORT
const struct ccdigest_info *ccsha256_di(void);

CC_EXPORT
const struct ccdigest_info ccsha256_ltc_di;

#define ccoid_sha256 CCOID("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01")
#define ccoid_sha256_len 11

/* SHA2-224 */
#define	CCSHA224_OUTPUT_SIZE 28

CC_EXPORT
const struct ccdigest_info *ccsha224_di(void);

CC_EXPORT
const struct ccdigest_info ccsha224_ltc_di;

#define ccoid_sha224 CCOID("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04")
#define ccoid_sha224_len 11

/* SHA512 */
#define CCSHA512_BLOCK_SIZE     128
#define	CCSHA512_OUTPUT_SIZE    64
#define	CCSHA512_STATE_SIZE     64

CC_EXPORT
const struct ccdigest_info *ccsha512_di(void);

extern const struct ccdigest_info ccsha512_ltc_di;

#define ccoid_sha512 CCOID("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03")
#define ccoid_sha512_len 11

/* SHA384 */
#define	CCSHA384_OUTPUT_SIZE  48

CC_EXPORT
const struct ccdigest_info *ccsha384_di(void);

extern const struct ccdigest_info ccsha384_ltc_di;

#define ccoid_sha384 CCOID("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02")
#define ccoid_sha384_len 11

/* SHA512/224 */
#define CCSHA512_224_BLOCK_SIZE     128
#define	CCSHA512_224_OUTPUT_SIZE    CCSHA224_OUTPUT_SIZE
#define	CCSHA512_224_STATE_SIZE     64

CC_EXPORT
const struct ccdigest_info *ccsha512_224_di(void);

extern const struct ccdigest_info ccsha512_224_ltc_di;

#define ccoid_sha512_224 CCOID("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05")
#define ccoid_sha512_224_len 11

/* SHA512/256 */
#define CCSHA512_256_BLOCK_SIZE     128
#define	CCSHA512_256_OUTPUT_SIZE    CCSHA256_OUTPUT_SIZE
#define	CCSHA512_256_STATE_SIZE     64

CC_EXPORT
const struct ccdigest_info *ccsha512_256_di(void);

extern const struct ccdigest_info ccsha512_256_ltc_di;

#define ccoid_sha512_256 CCOID("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06")
#define ccoid_sha512_256_len 11

CC_END_DECLS

#endif /* __CORECRYPTO_CCSHA2_H__ */
