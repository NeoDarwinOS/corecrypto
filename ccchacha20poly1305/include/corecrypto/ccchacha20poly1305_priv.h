/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCCHACHA20POLY1305_PRIV_H__
#define __CORECRYPTO_CCCHACHA20POLY1305_PRIV_H__

#include <corecrypto/ccchacha20poly1305.h>

//
// These functions could be useful for clients.
//
// ccchacha20 is used by CommonCrypto, actually.
//

CC_EXPORT
cc_error_t ccchacha20_init(ccchacha20_ctx *ctx, const void *key);

CC_EXPORT
cc_error_t ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter);

CC_EXPORT
cc_error_t ccchacha20_setnonce(ccchacha20_ctx *ctx, const void *nonce);

CC_EXPORT
cc_error_t ccchacha20_update(ccchacha20_ctx *ctx, size_t nbytes, const void *in, void *out);

CC_EXPORT
cc_error_t ccchacha20_reset(ccchacha20_ctx *ctx);

CC_EXPORT
cc_error_t ccchacha20_final(ccchacha20_ctx *ctx);

CC_EXPORT
cc_error_t ccchacha20(const void *key,
                      const void *nonce,
                      uint32_t counter,
                      size_t nbytes,
                      const void *in,
                      void *out);

CC_EXPORT
cc_error_t ccpoly1305_init(ccpoly1305_ctx *ctx, const void *key);

CC_EXPORT
cc_error_t ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const void *in);

CC_EXPORT
cc_error_t ccpoly1305_final(ccpoly1305_ctx *ctx, void *tag);

CC_EXPORT
cc_error_t ccpoly1305(const void *key, size_t nbytes, const void *in, void *tag);

#endif /* __CORECRYPTO_CCCHACHA20POLY1305_PRIV_H__  */
