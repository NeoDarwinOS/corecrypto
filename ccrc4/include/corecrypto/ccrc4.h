/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCRC4_H__
#define __CORECRYPTO_CCRC4_H__

#include <corecrypto/cc.h>

CC_BEGIN_DECLS

cc_aligned_struct(16) ccrc4_ctx;

#define ccrc4_ctx_decl(size, name) cc_ctx_decl(ccrc4_ctx, size, name)
#define ccrc4_ctx_clear(size, name) cc_clear(size, name)

struct ccrc4_info {
    size_t size;

    void (*init)(ccrc4_ctx *ctx,
                 size_t key_length,
                 const void *key);

    void (*crypt)(ccrc4_ctx *ctx,
                  size_t nbytes,
                  const void *in,
                  void *out);
};

CC_END_DECLS

#endif /* __CORECRYPTO_CCRC4_H__  */
