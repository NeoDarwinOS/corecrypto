/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_H__
#define __CORECRYPTO_CCMODE_H__

#include <corecrypto/ccmode_impl.h>
#include <corecrypto/ccmode_factory.h>

CC_BEGIN_DECLS

/*!
 * @group ccmode
 *
 * @discussion
 * The ccmode set of APIs are facilitators for ciphers in various modes of operations, as specified under NIST SP800-38 and it's series of
 * documents, SP800-30A, SP800-30C, and SP800-30D.
 *
 * You can locate these documents here:
 *      NIST SP800-38A, Recommendation for Block Cipher Modes of Operation,
 *                      https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
 *
 *      NIST SP800-38C, Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality,
 *                      https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38c.pdf
 *
 *      NIST SP800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC,
 *                      https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
 * 
 * These APIs enable cross-platform cipher support, with a low-overhead and straightforward interface.
 */

/* Currently 16 for AES. Change when required. */
#define CCMODE_MAX_BLOCK_SIZE   16

/*
 * ECB mode declarations
 */

/*!
 * @defined     ccecb_ctx_decl
 *              Declare an ECB context with a given name.
 */
#define ccecb_ctx_decl(size, name) cc_ctx_decl(ccecb_ctx, size, name)

/*!
 * @defined     ccecb_ctx_clear
 *              Clear an ECB context with a given name.
 */
#define ccecb_ctx_clear(size, name) cc_clear(size, name)

/*!
 * @function ccecb_context_size
 * Gets the size of the cipher implementation's internal state.
 *
 * @abstract    Gets the size of the ECB implementation
 *
 * @param       ecb
 *              The cipher implementation.
 *
 * @result      Returns the size of the ECB implementation
 */
CC_EXPORT
size_t ccecb_context_size(const struct ccmode_ecb *ecb) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccecb_block_size
 * Gets the block size of the cipher.
 *
 * @abstract    Gets the block size of the ECB implementation
 *
 * @param       ecb
 *              The cipher implementation.
 *
 * @result      Returns the block size of the ECB implementation
 */
CC_EXPORT
size_t ccecb_block_size(const struct ccmode_ecb *ecb) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccecb_init
 * Initialises the cipher context for encryption or decryption.
 *
 * @abstract    Initialises the cipher.
 *
 * @param       ecb
 *              The ECB implementation.
 *
 * @param       ctx
 *              The ECB context.
 *
 * @param       key_size
 *              The size of the symmetric key.
 *
 * @param       key
 *              The symmetric key.
 *
 * @result      Returns a non-zero error code if the initialisation failed.
 */
CC_EXPORT
cc_error_t ccecb_init(const struct ccmode_ecb *ecb,
                      ccecb_ctx *ctx,
                      size_t key_size,
                      const void *key) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccecb_update
 * Runs the symmetric encryption or decryption operation on the number of blocks specified.
 * It should be noted that bounds checking on the in and out pointers are the client's responsibility.
 *
 * @abstract    Operates on data using the cipher contained.
 *
 * @param       ecb
 *              The ECB implementation.
 *
 * @param       ctx
 *              The ECB context.
 *
 * @param       nblocks
 *              The number of blocks to encrypt or decrypt
 *
 * @param       in
 *              The plaintext or ciphertext to encrypt or decrypt
 *
 * @param       out
 *              The plaintext or ciphertext to write to.
 *
 * @result      Returns a non-zero error code if the operation failed.
 */
CC_EXPORT
cc_error_t ccecb_update(const struct ccmode_ecb *ecb,
                        const ccecb_ctx *ctx,
                        size_t nblocks,
                        const void *in,
                        void *out) CORECRYPTO_API_AVAILABLE_2012;


/*!
 * @function ccecb_one_shot
 * Runs an encrypt/decrypt operation in one shot rather than the client calling every function.
 * This is a convenience function for quick one-and-done operations rather than ones that will span
 * more than a few cycles.
 *
 * @abstract    Runs a full encrypt operation on a given data chunk.
 *
 * @param       ecb
 *              The ECB implementation.
 *
 * @param       key_size
 *              The size of the symmetric key.
 *
 * @param       key
 *              The symmetric key.
 *
 * @param       nblocks
 *              The number of blocks to encrypt or decrypt
 *
 * @param       in
 *              The plaintext or ciphertext to encrypt or decrypt
 *
 * @param       out
 *              The plaintext or ciphertext to write to.
 *
 * @result      Returns a non-zero error code if the operation failed.
 */
CC_EXPORT
cc_error_t ccecb_one_shot(const struct ccmode_ecb *ecb,
                          size_t key_size,
                          const void *key,
                          size_t nblocks,
                          const void *in,
                          void *out) CORECRYPTO_API_AVAILABLE_2012;


#define cccbc_ctx_decl(size, name) cc_ctx_decl(cccbc_ctx, size, name)
#define cccbc_ctx_clear(size, name) cc_clear(size, name)

#define cccbc_iv_decl(size, name) cc_ctx_decl(cccbc_iv, size, name)
#define cccbc_iv_clear(size, name) cc_clear(size, name)

/*!
 * @function cccbc_context_size
 * Gets the size of the cipher implementation's internal state.
 *
 * @abstract    Gets the size of the CBC implementation
 *
 * @param       cbc
 *              The cipher implementation.
 *
 * @result      Returns the size of the CBC implementation
 */
CC_EXPORT
size_t cccbc_context_size(const struct ccmode_cbc *cbc) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function cccbc_block_size
 * Gets the block size of the cipher.
 *
 * @abstract    Gets the block size of the CBC implementation
 *
 * @param       cbc
 *              The cipher implementation.
 *
 * @result      Returns the block size of the CBC implementation
 */
CC_EXPORT
size_t cccbc_block_size(const struct ccmode_cbc *cbc) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function cccbc_init
 * Initialises the cipher context for encryption or decryption.
 *
 * @abstract    Initialises the cipher.
 *
 * @param       cbc
 *              The CBC implementation.
 *
 * @param       ctx
 *              The CBC context.
 *
 * @param       key_size
 *              The size of the symmetric key.
 *
 * @param       key
 *              The symmetric key.
 *
 * @result      Returns a non-zero error code if the initialisation failed.
 */
CC_EXPORT
cc_error_t cccbc_init(const struct ccmode_cbc *cbc,
                      cccbc_ctx *ctx,
                      size_t key_size,
                      const void *key) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function cccbc_set_iv
 * Initialises the IV context for the CBC mode.
 *
 * @abstract    Prepares the IV.
 *
 * @result      Returns a non-zero error code if the initialisation failed.
 */
CC_EXPORT
cc_error_t cccbc_set_iv(const struct ccmode_cbc *mode,
                        cccbc_iv *iv_ctx,
                        const void *iv) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function cccbc_update
 * Runs the symmetric encryption/decryption operation on the number of blocks specified.
 * It should be noted that bounds checking on the in and out pointers are the client's responsibility.
 *
 * @abstract    Operates on data using the cipher contained.
 *
 * @result      Returns a non-zero error code if the operation failed.
 */
CC_EXPORT
cc_error_t cccbc_update(const struct ccmode_cbc *cbc,
                        const cccbc_ctx *ctx,
                        cccbc_iv *iv,
                        size_t nblocks,
                        const void *in,
                        void *out) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function cccbc_one_shot
 * Runs an encrypt/decrypt operation in one shot rather than the client calling every function.
 * This is a convenience function for quick one-and-done operations rather than ones that will span
 * more than a few cycles.
 *
 * @abstract    Runs a full encrypt operation on a given data chunk.
 *
 * @result      Returns a non-zero error code if the operation failed.
 */
CC_EXPORT
cc_error_t cccbc_one_shot(const struct ccmode_cbc *cbc,
                          size_t key_length,
                          const void *key,
                          size_t nblocks,
                          const void *iv,
                          const void *in,
                          void *out) CORECRYPTO_API_AVAILABLE_2012;

#define ccctr_ctx_decl(size, name) cc_ctx_decl(ccctr_ctx, size, name)
#define ccctr_ctx_clear(size, name) cc_clear(size, name)

/*!
 * @function ccctr_context_size
 * Gets the size of the cipher implementation's internal state.
 *
 * @abstract    Gets the size of the CTR implementation
 *
 * @result      Returns the size of the CTR implementation
 */
CC_EXPORT
size_t ccctr_context_size(const struct ccmode_ctr *ctr) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccctr_block_size
 * Gets the block size of the cipher.
 *
 * @discussion  This does not provide the block size of the underlying cipher, and
 *              instead, provides a '1' as this mode operates through bytes rather than
 *              blocks.
 *
 * @abstract    Gets the block size of the CTR implementation
 *
 * @result      Returns the block size of the CTR implementation
 */
CC_EXPORT
size_t ccctr_block_size(const struct ccmode_ctr *ctr) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccctr_init
 * Initialises the cipher context for encryption or decryption.
 *
 * @abstract    Initialises the cipher.
 *
 * @result      Returns a non-zero error code if the initialisation failed.
 */
CC_EXPORT
cc_error_t ccctr_init(const struct ccmode_ctr *ctr,
                      ccctr_ctx *ctx,
                      size_t key_size,
                      const void *key,
                      const void *iv) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccctr_setctr
 * Sets the counter value in the CTR mode context, sized by the underlying ECB mode's block size.
 *
 * @abstract    Prepares the IV.
 *
 * @result      Returns a non-zero error code if the initialisation failed.
 */
CC_EXPORT
cc_error_t ccctr_setctr(const struct ccmode_ctr *ctr,
                        ccctr_ctx *ctx,
                        const void *counter);

/*!
 * @function ccctr_update
 * Runs the symmetric encryption/decryption operation on the number of blocks specified.
 * It should be noted that bounds checking on the in and out pointers are the client's responsibility.
 *
 * @abstract    Operates on data using the cipher contained.
 *
 * @result      Returns a non-zero error code if the operation failed.
 */
CC_EXPORT
cc_error_t ccctr_update(const struct ccmode_ctr *ctr,
                        ccctr_ctx *ctx,
                        size_t nbytes,
                        const void *in,
                        void *out) CORECRYPTO_API_AVAILABLE_2012;

/*!
 * @function ccctr_one_shot
 * Runs an encrypt/decrypt operation in one shot rather than the client calling every function.
 * This is a convenience function for quick one-and-done operations rather than ones that will span
 * more than a few cycles.
 *
 * @abstract    Runs a full encrypt operation on a given data chunk.
 *
 * @result      Returns a non-zero error code if the operation failed.
 */
CC_EXPORT
cc_error_t ccctr_one_shot(const struct ccmode_ctr *ctr,
                          size_t key_length,
                          const void *key,
                          const void *iv,
                          size_t nbytes,
                          const void *in,
                          void *out) CORECRYPTO_API_AVAILABLE_2012;


#define ccxts_ctx_decl(size, name) cc_ctx_decl(ccxts_ctx, size, name)
#define ccxts_ctx_clear(size, name) cc_clear(size, name)

#define ccxts_tweak_decl(size, name) cc_ctx_decl(ccxts_tweak, size, name)
#define ccxts_tweak_clear(size, name) cc_clear(size, name)

CC_EXPORT
size_t ccxts_context_size(const struct ccmode_xts *xts) CORECRYPTO_API_AVAILABLE_2012;

CC_EXPORT
size_t ccxts_block_size(const struct ccmode_xts *xts) CORECRYPTO_API_AVAILABLE_2012;

CC_EXPORT
cc_error_t ccxts_init(const struct ccmode_xts *xts,
                      ccxts_ctx *ctx,
                      size_t key_size,
                      const void *data_key,
                      const void *tweak_key);

CC_EXPORT
cc_error_t ccxts_set_tweak(const struct ccmode_xts *xts,
                           ccxts_ctx *ctx,
                           ccxts_tweak *tweak,
                           const void *iv);

CC_EXPORT
void *ccxts_update(const struct ccmode_xts *xts,
                   ccxts_ctx *ctx,
                   ccxts_tweak *tweak,
                   size_t nblocks,
                   const void *in,
                   void *out);


#define ccgcm_ctx_decl(size, name) cc_ctx_decl(ccgcm_ctx, size, name)
#define ccgcm_ctx_clear(size, name) cc_clear(size, name)

// ccgcm needs to be done for kernel and aead... don't forget ecies... and ecc in general ngl. 

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_H__ */
