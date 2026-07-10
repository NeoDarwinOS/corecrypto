/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_IMPL_H__
#define __CORECRYPTO_CCMODE_IMPL_H__

#include <corecrypto/cc.h>

CC_BEGIN_DECLS

/*
 * API NOTES:
 *
 * Each of the 'custom' entries in a cipher mode structure is an additional structure, which can be entirely arbitrary
 * if the implementation so chooses.
 *
 * This is used in the 'Factory' variant of modes, where the base ECB context is stored in the custom fields.
 *
 * For supplemental implementations, this could be useful for storing constant data that is only ever needed at init time.
 *
 * For these APIs, I highly reccomend reading up on the cipher modes that underpin them.
 *
 * Specifically:
 *  NIST SP800-38A, Recommendation for Block Cipher Modes of Operation,
 *                  https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
 *
 *  NIST SP800-38C, Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality,
 *                  https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38c.pdf
 *
 *  NIST SP800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC,
 *                  https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
 *
 *  XTS mode is an IEEE thing, the documentation is most likely not freely available.
 */

/*
 * ECB - 'Electronic Codebook'
 *
 * ECB mode boils down to the underlying cipher, however the input data is split into blocks.
 * These blocks are then ran through said cipher, producing the encrypted output.
 *
 * Arguably, this is the most simple one to implement, given we just need the cipher.
 */
cc_aligned_struct(16) ccecb_ctx;

struct ccmode_ecb {
    size_t size;
    size_t block_size;

    cc_error_t (*init)(const struct ccmode_ecb *ecb,
                       ccecb_ctx *ctx,
                       size_t key_size,
                       const void *key);

    cc_error_t (*ecb)(const ccecb_ctx *ctx, size_t nblocks, const void *in,
                      void *out);

    /* These fields are ones we really don't care about- they aren't used anywhere in Security or other frameworks. */
    void *pad;
    int pad2;

    /* API NOTE: This is yet another extension */
    const char *impl_name;
};

/*
 * CBC - 'Cipher Block Chaining'
 *
 * CBC itself is rather simple really. The sequence of encrypted blocks becomes XOR'd with the last processed block.
 * The IV is what starts the XORing chain, adding more randomness to the overall encrypted product.
 *
 * This one is a rather easy mode, and has historial use in BitLocker as a former FDE option.
 *
 * Apple also uses AES in CBC mode for encrypting their firmware payloads.
 *
 * Nowadays, we just use XTS in either AES-128 or AES-256 for FDE.
 */
cc_aligned_struct(16) cccbc_ctx;
cc_aligned_struct(16) cccbc_iv;

struct ccmode_cbc {
    size_t size;
    size_t block_size;

    cc_error_t (*init)(const struct ccmode_cbc *cbc,
                       cccbc_ctx *ctx,
                       size_t key_size,
                       const void *key);

    cc_error_t (*cbc)(const cccbc_ctx *ctx,
                      cccbc_iv *iv,
                      size_t nblocks,
                      const void *in,
                      void *out);

    const void *custom;

    /* API NOTE: This is yet another extension */
    const char *impl_name;
};

/*
 * CFB - 'Cipher Feedback Mode'
 *
 *
 */

/*
 * OFB - 'Output Feedback Mode'
 */

/*
 * CTR - 'Counter Mode'
 *
 * CTR mode is used for various auxiliary functions. PRNGs.
 */
cc_aligned_struct(16) ccctr_ctx;

struct ccmode_ctr {
    size_t size;
    size_t block_size;
    size_t ecb_block_size;

    cc_error_t (*init)(const struct ccmode_ctr *ctr,
                       ccctr_ctx *ctx,
                       size_t key_size,
                       const void *key,
                       const void *iv);

    cc_error_t (*setctr)(const struct ccmode_ctr *ctr,
                         ccctr_ctx *ctx,
                         const void *counter);

    cc_error_t (*ctr)(ccctr_ctx *ctx,
                      size_t nbytes,
                      const void *in,
                      void *out);

    const void *custom;

    const char *impl_name;
};

/*
 * GCM - 'Galois Counter Mode'
 *
 * GCM is used as an all-encompassing AEAD for networking security.
 */
cc_aligned_struct(16) ccgcm_ctx;

/*
 * XTS - 'XEX Tweakable Block Ciphertext Stealing'
 *
 * XTS is THE full-disk encryption algorithm. I think we know why we need this.
 */
cc_aligned_struct(16) ccxts_ctx;

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_IMPL_H__ */
