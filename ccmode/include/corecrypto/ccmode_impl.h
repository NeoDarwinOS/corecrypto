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

/*!
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

/*!
 * @group ccmode_ecb
 * The ECB mode of operation boils down to the underlying cipher, with data segmented into 'blocks' according to the cipher's
 * processing capabilties. For example, AES has a block size of 128 bits, or 16 bytes.
 *
 * It is unwise to use ECB mode raw, and- within corecrypto, is commonly used to facilitate other types of cipher modes, such as
 * CBC.
 */

/*!
 * @typedef  ccecb_ctx
 * This is an opaque structure, and implementations of ciphers shall specify their specific size in ccmode_ecb
 *
 * @abstract Cipher ECB mode context
 */
cc_aligned_struct(16) ccecb_ctx;

/*!
 * @struct  ccmode_ecb
 * This structure faciliates an interface to utilise varying kinds of ciphers.
 *
 * @field   size
 *          The size of the ECB context used by the cipher.
 *
 * @field   block_size
 *          The block size of the cipher.
 *
 * @field   init
 *          The function pointer to initialise a context.
 *
 * @field   ecb
 *          The function pointer to either encrypt or decrypt blocks of
 *          data.
 *
 * @field   pad
 *          This is a compatibility padding to not break anything in case this field is used.
 *
 * @field   pad2
 *          This is a compatibility padding to not break anything in case this field is used.
 * 
 * @field   impl_name
 *          A null terminated ASCII string with the shortname of an implementation 
 *
 * @abstract Cipher ECB mode
 */
struct ccmode_ecb {
    size_t size;
    size_t block_size;

    cc_error_t (*init)(const struct ccmode_ecb *ecb,
                       ccecb_ctx *ctx,
                       size_t key_size,
                       const void *key);

    cc_error_t (*ecb)(const ccecb_ctx *ctx, size_t nblocks, const void *in,
                      void *out);

    void *pad;
    int pad2;
    const char *impl_name;
};

/*!
 * @group ccmode_cbc
 * The CBC mode of operation centres around the concept of an Initialisation Vector, being used and XORed with the first set of ciphertext, thus
 * initialising a chain of encryption created by subsequent blocks processed.
 */

/*!
 * @typedef  cccbc_ctx
 * This is an opaque structure, and implementations of ciphers shall specify their specific size in ccmode_cbc
 *
 * @abstract Cipher CBC mode context
 */
cc_aligned_struct(16) cccbc_ctx;

/*!
 * @typedef  cccbc_iv
 * This is an opaque structure, and normally is handled by cccbc_set_iv
 *
 * @abstract Cipher CBC IV context
 */
cc_aligned_struct(16) cccbc_iv;

/*!
 * @struct  ccmode_cbc
 * This structure faciliates an interface to utilise varying kinds of ciphers.
 *
 * @field   size
 *          The size of the CBC context used by the cipher.
 *
 * @field   block_size
 *          The block size of the cipher.
 *
 * @field   init
 *          The function pointer to initialise a context.
 *
 * @field   cbc
 *          The function pointer to either encrypt or decrypt blocks of
 *          data.
 *
 * @field   custom
 *          This is an extra field for an implementation to use at runtime.
 * 
 * @field   impl_name
 *          A null terminated ASCII string with the shortname of an implementation 
 *
 * @abstract Cipher CBC mode
 */
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
 * CFB - 'Cipher Feedback Mode' (using the native block size)
 */
cc_aligned_struct(16) cccfb_ctx;

struct ccmode_cfb {
    size_t size;
    size_t block_size;

    cc_error_t (*init)(const struct ccmode_cfb *ofb,
                       cccfb_ctx *ctx,
                       size_t key_size,
                       const void *key,
                       const void *iv);

    cc_error_t (*cfb)(cccfb_ctx *ctx,
                      size_t nbytes,
                      const void *in,
                      void *out);

    const void *custom;
};

/*
 * CFB8 - 'Cipher Feedback Mode' (using 8-bits)
 */
cc_aligned_struct(16) cccfb8_ctx;

struct ccmode_cfb8 {
    size_t size;
    size_t block_size;

    cc_error_t (*init)(const struct ccmode_cfb8 *ofb,
                       cccfb8_ctx *ctx,
                       size_t key_size,
                       const void *key,
                       const void *iv);

    cc_error_t (*cfb8)(cccfb8_ctx *ctx,
                       size_t nbytes,
                       const void *in,
                       void *out);

    const void *custom;
};

/*
 * OFB - 'Output Feedback Mode'
 */
cc_aligned_struct(16) ccofb_ctx;

struct ccmode_ofb {
    size_t size;
    size_t block_size;

    cc_error_t (*init)(const struct ccmode_ofb *ofb,
                       ccofb_ctx *ctx,
                       size_t key_size,
                       const void *key,
                       const void *iv);

    cc_error_t (*ofb)(ccofb_ctx *ctx,
                      size_t nbytes,
                      const void *in,
                      void *out);

    const void *custom;
};

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

#define CCMODE_GCM_DECRYPTOR 78647
#define CCMODE_GCM_ENCRYPTOR 4073947

struct ccmode_gcm {
    size_t size;
    int encdec;
    size_t block_size;
    
    cc_error_t (*init)(const struct ccmode_gcm *gcm,
                       ccgcm_ctx *cyx,
                       size_t key_size,
                       const void *key);
    
    cc_error_t (*set_iv)(ccgcm_ctx *ctx,
                         size_t iv_size,
                         const void *iv);
    
    cc_error_t (*gmac)(ccgcm_ctx *ctx,
                       size_t nbytes,
                       const void *in);
    
    cc_error_t (*gcm)(ccgcm_ctx *ctx,
                      size_t nbytes,
                      const void *in,
                      void *out);
    
    cc_error_t (*finalize)(ccgcm_ctx *ctx,
                           size_t tag_size,
                           void *tag);
    
    cc_error_t (*reset)(ccgcm_ctx *ctx);
    
    const void *custom;
};

/*
 * XTS - 'XEX Tweakable Block Ciphertext Stealing'
 *
 * XTS is THE full-disk encryption algorithm. I think we know why we need this.
 */
cc_aligned_struct(16) ccxts_ctx;
cc_aligned_struct(16) ccxts_tweak;

struct ccmode_xts {
    size_t size;
    size_t tweak_size;
    size_t block_size;
    
    cc_error_t (*init)(const struct ccmode_xts *xts,
                       ccxts_ctx *ctx,
                       size_t key_size,
                       const void *data_key,
                       const void *tweak_key);
    
    cc_error_t (*key_sched)(const struct ccmode_xts *xts,
                            ccxts_ctx *ctx,
                            size_t key_size,
                            const void *data_key,
                            const void *tweak_key);
    
    cc_error_t (*set_tweak)(const ccxts_ctx *ctx,
                            ccxts_tweak *tweak,
                            const void *iv);
    
    void *(*xts)(const ccxts_ctx *ctx,
                 ccxts_tweak *tweak,
                 size_t nblocks,
                 const void *in,
                 void *out);
    
    const void *custom;
    const void *custom1;
};

/*
 * CCM - Counter with CBC-MAC
 *
 * Used for WPA2. This would be very useful for SoftMAC implementations of a future 802.11 stack.
 *
 * Introduced in 2014.
 */
cc_aligned_struct(16) ccccm_ctx;
cc_aligned_struct(16) ccccm_nonce;

struct ccmode_ccm {
    size_t size;
    size_t nonce_size;
    size_t block_size;
    
    cc_error_t (*init)(const struct ccmode_ccm *ccm,
                       ccccm_ctx *ctx,
                       size_t key_size,
                       const void *key);
    
    cc_error_t (*set_iv)(ccccm_ctx *ctx,
                         ccccm_nonce *nonce_ctx,
                         size_t nonce_len,
                         const void *nonce,
                         size_t mac_size,
                         size_t auth_len,
                         size_t data_len);
    
    cc_error_t (*cbcmac)(ccccm_ctx *ctx,
                         ccccm_nonce *nonce,
                         size_t nbytes,
                         const void *in);
    
    cc_error_t (*ccm)(ccccm_ctx *ctx,
                      ccccm_nonce *nonce,
                      size_t nbytes,
                      const void *in,
                      void *out);
    
    cc_error_t (*finalize)(ccccm_ctx *ctx,
                           ccccm_nonce *nonce,
                           void *mac);
    
    cc_error_t (*reset)(ccccm_ctx *ctx,
                        ccccm_nonce *nonce);
    
    const void *custom;

    bool enc_mode;
};

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_IMPL_H__ */
