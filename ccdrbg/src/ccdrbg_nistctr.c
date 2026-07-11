/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccn.h>

#define DRBG_STATE(x) ((struct ccdrbg_nistctr_state *)x)
#define DRBG_STATE_CTR_MODE(x) DRBG_STATE(x)->ctr_mode
#define DRBG_STATE_KEY_LENGTH(x) DRBG_STATE(x)->key_length
#define DRBG_STATE_BLOCK_SIZE(x) DRBG_STATE_CTR_MODE(x)->ecb_block_size

#define DRBG_STATE_CTR_KEY(x) DRBG_STATE(x)->ctr_ctx
#define DRBG_STATE_DF_KEY(x) DRBG_STATE(x)->df_ctx

#define DRBG_STATE_OUTLEN(x) DRBG_STATE_KEY_LENGTH(x)

#define DRBG_STATE_SEEDLEN(x) (DRBG_STATE_KEY_LENGTH(x) + DRBG_STATE_BLOCK_SIZE(x))

#define DRBG_BCC_STORAGE_BLOCKS_NUM(x) cc_ceiling(DRBG_STATE_SEEDLEN(x)+DRBG_STATE_OUTLEN(x),DRBG_STATE_OUTLEN(x))
#define DRBG_BCC_STORAGE_SIZE(x) (DRBG_BCC_STORAGE_BLOCKS_NUM(x) * DRBG_STATE_OUTLEN(x))

#define DRBG_STATE_SIZE(mode) (ccn_sizeof_size(sizeof(struct ccdrbg_nistctr_state))) +     \
                              (2 * ccn_sizeof_size(mode->size)) +                          \
                              (7 * ccn_sizeof_size(mode->ecb_block_size))

#define MAX_KEY_SIZE            CCAES_KEY_SIZE_256
#define MAX_BLOCK_SIZE          CCAES_BLOCK_SIZE
#define MAX_SEED_SIZE           MAX_KEY_SIZE + MAX_BLOCK_SIZE
#define MAX_BCC_STORAGE_SIZE    48
#define COUNTER_LENGTH  8

/* Need to determine what fields we need in-memory for the DRBG to function. And to never. Ever. have to call malloc. */
struct ccdrbg_nistctr_state {
    uint8_t key[MAX_KEY_SIZE];
    uint8_t V[MAX_BLOCK_SIZE];
    uint64_t reseed_counter;

    /* Fields that the custom should provide. */
    const struct ccmode_ctr *ctr_mode;

    /* (key_length * 8) == Security strength, according to SP800-58A */
    size_t key_length;

    /* Are we strictly adhereing to the seed schdedule? */
    bool strictFIPS;

    /* Self-explanatory. */
    bool use_df;

    /* BCC stuff. */
    size_t bcc_pos;

    /* POINTERS BELOW THIS LINE ARE CONVENIENCE POINTERS TO AVOID MESSING WITH THE cc_unit SPACE */
    uint8_t *bcc_buf;
    uint8_t *bcc_initial_state;
    uint8_t *bcc_state;
    ccctr_ctx *ctr_ctx;
    ccctr_ctx *df_ctx;

    /*
     * cc_unit memory region
     *
     * layout should be as follows:
     * uint8_t _bcc_buf[DRBG_STATE_BLOCK_SIZE]
     * uint8_t _bcc_initial_state[DRBG_BCC_STORAGE_SIZE]
     * uint8_t _bcc_state[DRBG_BCC_STORAGE_SIZE]
     */
    cc_unit u[];
};

/*
 * Since we don't exactly have access to an ECB mode, and using another pointer opens up way to many cans of worms...
 *
 * Reuse the CTR context.
 */
static uint8_t zeroes[MAX_BLOCK_SIZE] = {0};

/*
 * The reason that this works is that it runs the ECB encryption on in when ccctr_update is ran.
 *
 * It then XOR's a zero-filled block, giving us what we want.
 *
 * Hacky, but it works.
 */
static void block_encrypt(const struct ccmode_ctr *ctr, ccctr_ctx *ctx, const void *in, void *out)
{
    ccctr_setctr(ctr, ctx, in);
    ccctr_update(ctr, ctx, ctr->ecb_block_size, zeroes, out);
}

/* Inner portion of bcc, since it's reusable. */
static void bcc_update(struct ccdrbg_nistctr_state *drbg, const void *in, size_t nblocks, void *out)
{
    const uint8_t *_data = (const uint8_t *)in;

    for (size_t i = 0; i < nblocks; i++) {
        cc_xor(DRBG_STATE_BLOCK_SIZE(drbg), out, out, _data);
        _data += DRBG_STATE_BLOCK_SIZE(drbg);
        block_encrypt(DRBG_STATE_CTR_MODE(drbg), DRBG_STATE_DF_KEY(drbg), out, out);
    }
}

static void bcc(struct ccdrbg_nistctr_state *state, const void *in, size_t n, void *out)
{
    cc_clear(DRBG_STATE_OUTLEN(state), out);
    bcc_update(state, in, n, out);
}

static const uint8_t df_key[MAX_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static void df_predf_init(struct ccdrbg_nistctr_state *state)
{
    size_t blks = DRBG_BCC_STORAGE_BLOCKS_NUM(state);
    uint8_t storage[MAX_BCC_STORAGE_SIZE];

    ccctr_init(state->ctr_mode, state->df_ctx, state->key_length, df_key, zeroes);
    
    for (size_t i = 0; i < blks; i++) {
        storage[(i * DRBG_STATE_BLOCK_SIZE(state)) + 3] = i;
    }
    
    bcc_update(state, storage, blks, state->bcc_initial_state);
}

cc_error_t ccdrbg_nistctr_init(const struct ccdrbg_info *info,
                               struct ccdrbg_state *state,
                               size_t entropy_length,
                               const void *entropy,
                               size_t none_length,
                               const void *nonce,
                               size_t ps_length,
                               const void *ps)
{
    struct ccdrbg_nistctr_state *_state = DRBG_STATE(state);
    const struct ccdrbg_nistctr_custom *_custom = (const struct ccdrbg_nistctr_custom *)info->custom;
    
    _state->ctr_mode = _custom->ctr;
    _state->key_length = _custom->key_length;
    _state->strictFIPS = _custom->strictFIPS;
    _state->use_df = _custom->use_df;
    
    cc_abort("not yet");
    
    //if (_state->use_df) {
    //    df_predf_init(_state);
    //}
    
    return CCERR_OK;
}

void ccdrbg_nistctr_done(struct ccdrbg_state *state)
{
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, DRBG_STATE_CTR_KEY(state));
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, DRBG_STATE_DF_KEY(state));
    cc_clear(sizeof(struct ccdrbg_nistctr_state), state);
}

void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom)
{
    info->size = DRBG_STATE_SIZE(custom->ctr);
    
    info->custom = custom;
}

