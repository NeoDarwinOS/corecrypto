/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDIGEST_H__
#define __CORECRYPTO_CCDIGEST_H__

#include <corecrypto/cc.h>
#include <corecrypto/ccasn1.h>

CC_BEGIN_DECLS

cc_aligned_struct(8) ccdigest_state;

typedef ccdigest_state *ccdigest_state_t;

#define ccdigest_u8(state) ((uint8_t *)((state)))
#define ccdigest_u16(state) ((uint16_t *)((state)))
#define ccdigest_u32(state) ((uint32_t *)((state)))
#define ccdigest_u64(state) ((uint64_t *)((state)))
#define ccdigest_ccn(state) ((cc_unit *)((state)))

/*
 * ccdigest_ctx layout:
 *
 * nbits (uint64_t)
 * state (state_size)
 * block (block_size)
 * num   (uint32_t)
 */
cc_aligned_struct(8) ccdigest_ctx;

typedef ccdigest_ctx *ccdigest_ctx_t;

#define ccdigest_state(di, ctx) ((ccdigest_state_t)(((ccdigest_u8(ctx) + sizeof(uint64_t)))))
#define ccdigest_state_u8(di, ctx) (ccdigest_u8(ccdigest_state(di, ctx)))
#define ccdigest_state_u16(di, ctx) (ccdigest_u16(ccdigest_state(di, ctx)))
#define ccdigest_state_u32(di, ctx) (ccdigest_u32(ccdigest_state(di, ctx)))
#define ccdigest_state_u64(di, ctx) (ccdigest_u64(ccdigest_state(di, ctx)))
#define ccdigest_state_ccn(di, ctx) (ccdigest_ccn(ccdigest_state(di, ctx)))

#define ccdigest_ctx_size(state_size, block_size) (sizeof(uint64_t) + state_size + block_size + sizeof(uint32_t))
#define ccdigest_ctx_decl(state_size, block_size, name) cc_ctx_decl(ccdigest_ctx, ccdigest_ctx_size(state_size, block_size), name)
#define ccdigest_ctx_clear(state_size, block_size, name) cc_clear((state_size + block_size), name);

#define ccdigest_nbits(di, ctx) (*(ccdigest_u64(ctx)))
#define ccdigest_data(di, ctx) ((ccdigest_u8(ctx) + sizeof(uint64_t) + di->state_size))
#define ccdigest_num(di, ctx)  (*((uint32_t *)(((ccdigest_u8(ctx)) + sizeof(uint64_t) + di->state_size + di->block_size))))

/* the digest's version of ccmode_xxx */
struct ccdigest_info {
    /* the size of the digest outputted */
    size_t output_size;

    /* the size of the hash state */
    size_t state_size;

    /* the size of block the hash needs to compress */
    size_t block_size;

    /* length of the oid */
    size_t oid_size;

    /* oid associated with this hash, ccoid_t formatted */
    ccoid_t oid;

    /* the initial state of the hash */
    const void *initial_state;

    void (*compress)(ccdigest_state_t state,
                     size_t nblocks,
                     const void *in);

    void (*final)(const struct ccdigest_info *di,
                  ccdigest_ctx_t ctx,
                  void *digest);

    /* for anyone wondering; this is the impl field, as of, whatever version. we dont care though. */
    int pad;

    const char *digest_impl_name;
};

#define ccdigest_di_size(di, name) ccdigest_ctx_size(di->state_size, di->block_size)
#define ccdigest_di_decl(di, name) ccdigest_ctx_decl(di->state_size, di->block_size, name)
#define ccdigest_di_clear(di, name) ccdigest_ctx_clear(di->state_size, di->block_size, name)

CC_EXPORT
void ccdigest(const struct ccdigest_info *di,
              size_t length,
              const void *data,
              void *digest);

CC_EXPORT
void ccdigest_init(const struct ccdigest_info *di,
                   ccdigest_ctx_t ctx);

CC_EXPORT
void ccdigest_update(const struct ccdigest_info *di,
                     ccdigest_ctx_t ctx,
                     size_t length,
                     const void *data);

CC_EXPORT
void ccdigest_final(const struct ccdigest_info *di,
                    ccdigest_ctx_t ctx,
                    void *digest);

CC_END_DECLS

#endif /* __CORECRYPTO_CCDIGEST_H__ */
