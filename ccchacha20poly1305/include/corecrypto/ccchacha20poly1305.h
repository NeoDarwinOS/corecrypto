/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCCHACHA20POLY1305_H__
#define __CORECRYPTO_CCCHACHA20POLY1305_H__

#include <corecrypto/cc.h>

#define CCCHACHA20_KEY_NBYTES   32
#define CCCHACHA20_BLOCK_NBYTES 64
#define CCCHACHA20_BLOCK_NBITS  (CCCHACHA20_BLOCK_NBYTES * 8)
#define CCCHACHA20_NONCE_NBYTES 12

typedef struct ccchacha20_ctx {
    uint32_t state[16];
    uint8_t buffer[CCCHACHA20_BLOCK_NBYTES];
    size_t leftover;
} ccchacha20_ctx;

#define CCPOLY1305_TAG_NBYTES 16

typedef struct ccpoly1305_ctx {
	uint32_t r0, r1, r2, r3, r4;
	uint32_t s1, s2, s3, s4;
	uint32_t h0, h1, h2, h3, h4;
	uint8_t	buf[16];
	size_t buf_used;
	uint8_t	key[16];
} ccpoly1305_ctx;

#define CCCHACHA20POLY1305_KEY_NBYTES       (CCCHACHA20_KEY_NBYTES)
#define CCCHACHA20POLY1305_NONCE_NBYTES     (CCCHACHA20_NONCE_NBYTES)
#define CCCHACHA20POLY1305_TAG_NBYTES       (CCPOLY1305_TAG_NBYTES)
#define CCCHACHA20POLY1305_TEXT_MAX_NBYTES  ((1ULL << 38) - 64ULL)

#define CCCHACHA20POLY1305_STATE_SETNONCE   1
#define CCCHACHA20POLY1305_STATE_AAD        2
#define CCCHACHA20POLY1305_STATE_ENCRYPT    3
#define CCCHACHA20POLY1305_STATE_DECRYPT    4
#define CCCHACHA20POLY1305_STATE_FINAL      5

// could accelerate maybe :P
struct ccchacha20poly1305_info {
    
};

typedef struct ccchacha20poly1305_ctx {
    struct ccchacha20_ctx chacha20_ctx;
	struct ccpoly1305_ctx poly1305_ctx;
	uint64_t aad_nbytes;
	uint64_t text_nbytes;
    uint8_t state;
} ccchacha20poly1305_ctx;

#endif /* __CORECRYPTO_CCCHACHA20POLY1305_H__  */
