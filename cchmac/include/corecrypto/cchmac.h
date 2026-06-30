/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCHMAC_H__
#define __CORECRYPTO_CCHMAC_H__

#include <corecrypto/ccdigest.h>

/*
 * API NOTES:
 *
 * HMAC is defined in RFC 2104, https://www.rfc-editor.org/info/rfc2104/
 */

CC_BEGIN_DECLS

cc_aligned_struct(8) cchmac_ctx;

typedef cchmac_ctx *cchmac_ctx_t;

#define cchmac_ctx_size(state_size, block_size)         (cc_pad_align(ccdigest_ctx_size(state_size, block_size) + state_size)
#define cchmac_ctx_decl(state_size, block_size, name)   cc_ctx_decl(cchmac_ctx, cchmac_ctx_size(state_size, block_size), name)
#define cchmac_ctx_clear(state_size, block_size, name)  cc_clear(cchmac_ctx_size(state_size, block_size), name)

#define cchmac_di_size(di)  cchmac_ctx_size(di->state_size, di->block_size)
#define cchmac_di_decl(di, name) cchmac_ctx_decl(di->state_size, di->block_size, name)
#define cchmac_di_clear(di, name) cchmac_ctx_clear(di->state_size, di->block_size, name)

#define cchmac_digest_ctx(di, hmac_ctx) ((ccdigest_ctx_t)(hmac_ctx))

#define cchmac_data(di, hmac_ctx)       (ccdigest_data(di, cchmac_digest_ctx(di, hmac_ctx)))
#define cchmac_num(di, hmac_ctx)        (ccdigest_num(di, cchmac_digest_ctx(di, hmac_ctx)))
#define cchmac_nbits(di, hmac_ctx)      (ccdigest_nbits(di, cchmac_digest_ctx(di, hmac_ctx)))

/* use a full ccdigest context for istate since it accumulates the message */
#define cchmac_istate(di, hmac_ctx)     (ccdigest_state(di, cchmac_digest_ctx(di, hmac_ctx)))
#define cchmac_istate8(di, hmac_ctx)    (ccdigest_u8(cchmac_istate(di, hmac_ctx)))
#define cchmac_istate16(di, hmac_ctx)   (ccdigest_u16(cchmac_istate(di, hmac_ctx)))
#define cchmac_istate32(di, hmac_ctx)   (ccdigest_u32(cchmac_istate(di, hmac_ctx)))
#define cchmac_istate64(di, hmac_ctx)   (ccdigest_u64(cchmac_istate(di, hmac_ctx)))
#define cchmac_istateccn(di, hmac_ctx)  (ccdigest_ccn(cchmac_istate(di, hmac_ctx)))

#define cchmac_ostate(di, hmac_ctx)     ((ccdigest_state_t)(((uint8_t *)hmac_ctx) + cc_pad_align(cchmac_di_size(di))))
#define cchmac_ostate8(di, hmac_ctx)    (ccdigest_u8(cchmac_ostate(di, hmac_ctx)))
#define cchmac_ostate16(di, hmac_ctx)   (ccdigest_u16(cchmac_ostate(di, hmac_ctx)))
#define cchmac_ostate32(di, hmac_ctx)   (ccdigest_u32(cchmac_ostate(di, hmac_ctx)))
#define cchmac_ostate64(di, hmac_ctx)   (ccdigest_u64(cchmac_ostate(di, hmac_ctx)))
#define cchmac_ostateccn(di, hmac_ctx)  (ccdigest_ccn(cchmac_ostate(di, hmac_ctx)))


void cchmac_init(const struct ccdigest_info *di,
                 cchmac_ctx_t ctx,
                 size_t key_length,
                 const void *key);

void cchmac_update(const struct ccdigest_info *di,
                   cchmac_ctx_t ctx,
                   size_t data_length,
                   const void *data);

void cchmac_final(const struct ccdigest_info *di,
                  cchmac_ctx_t ctx,
                  void *mac);

void cchmac(const struct ccdigest_info *di,
            size_t key_length,
            const void *key,
            size_t data_length,
            const void *data,
            void *mac);

CC_END_DECLS

#endif /* __CORECRYPTO_CCHMAC_H__ */
