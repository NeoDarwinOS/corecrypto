/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto/cc.h"
#include "corecrypto/cc_debug.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode_internal.h>
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

#define DRBG_STATE_SIZE(custom) (ccn_sizeof_size(sizeof(struct ccdrbg_nistctr_state))) +            \
                                (2 * ccn_sizeof_size(custom->ctr->size)) +                          \
                                (ccn_sizeof_size(custom->key_length)) +                             \
                                (2 * ccn_sizeof_size((cc_ceiling((custom->key_length + custom->ctr->ecb_block_size), custom->ctr->ecb_block_size) * 8)))

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
    uint8_t *bcc_initial_state;
    uint8_t *bcc_scratch;
    uint8_t *bcc_tmp;
    ccctr_ctx *ctr_ctx;
    ccctr_ctx *df_ctx;

    /*
     * cc_unit memory region
     *
     * layout should be as follows:
     * uint8_t _bcc_scratch[DRBG_STATE_BLOCK_SIZE]
     * uint8_t _bcc_initial_state[DRBG_BCC_STORAGE_SIZE]
     * uint8_t _bcc_tmp[DRBG_BCC_STORAGE_SIZE]
     * ccctr_ctx _ctr_ctx
     * ccctr_ctx _df_ctx
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

    cc_debug_log("bcc_update in: %p", in);
    cc_debug_log("bcc_update out: %p", out);
    cc_debug_log("bcc_update nblocks: %zd", nblocks);

    for (size_t i = 0; i < nblocks; i++) {
        cc_debug_log("bcc_update XOR ENTER");
        cc_xor(DRBG_STATE_BLOCK_SIZE(drbg), out, out, _data);
        cc_debug_log("bcc_update XOR EXIT");
        _data += DRBG_STATE_BLOCK_SIZE(drbg);
        cc_debug_log("bcc_update _data %p", _data);
        cc_debug_log("bcc_update block_encrypt ENTER");
        block_encrypt(DRBG_STATE_CTR_MODE(drbg), DRBG_STATE_DF_KEY(drbg), out, out);
        cc_debug_log("bcc_update block_encrypt EXIT");
    }

    cc_debug_log("bcc_update EXIT");
}

static void bcc(struct ccdrbg_nistctr_state *state, const void *in, size_t n, void *out)
{
    cc_clear(DRBG_STATE_OUTLEN(state), out);
    bcc_update(state, in, n, out);
}

static void df_bcc_update(struct ccdrbg_nistctr_state *state, const void *in, size_t nbytes);

static void df_bcc_init(struct ccdrbg_nistctr_state *state, uint32_t l, uint32_t n)
{
    uint32_t s[2];

    state->bcc_pos = 0;
    cc_clear(DRBG_STATE_OUTLEN(state), state->bcc_scratch);

    s[0] = cc_h2be32(l);
    s[1] = cc_h2be32(n);

    /* accumulate the first two parts of the S variable... */
    df_bcc_update(state, s, sizeof(s));
}

static void df_bcc_update(struct ccdrbg_nistctr_state *state, const void *in, size_t nbytes)
{
    size_t bytes = nbytes;
    size_t blks = nbytes / DRBG_STATE_BLOCK_SIZE(state);
    size_t leftover = (DRBG_STATE_BLOCK_SIZE(state) - state->bcc_pos);
    const uint8_t *_in = (const uint8_t *)in;

    cc_debug_log("df_bcc_update bcc_pos: %zd", state->bcc_pos);
    cc_debug_log("df_bcc_update nbytes: %zd", nbytes);
    cc_debug_log("df_bcc_update blks: %zd", blks);

    cc_debug_log("df_bcc_update _in 0 %p", _in);

    if (state->bcc_pos) {
        cc_debug_log("df_bcc_update bcc_pos >>");
        cc_copy(leftover, (state->bcc_scratch + leftover), _in);
        bcc_update(state, state->bcc_scratch, 1, state->bcc_tmp);
        state->bcc_pos = 0;
        _in += leftover;
        bytes -= leftover;
    }

    cc_debug_log("df_bcc_update _in 1 %p", _in);

    if (bytes >= DRBG_STATE_BLOCK_SIZE(state)) {
        cc_debug_log("df_bcc_update _in 2 %p", _in);
        bcc_update(state, _in, blks, state->bcc_tmp);
        cc_debug_log("df_bcc_update bcc_update EXIT");
        _in += (blks * DRBG_STATE_BLOCK_SIZE(state));
        bytes -= (blks * DRBG_STATE_BLOCK_SIZE(state));
    }

    if (bytes) {
        cc_debug_log("df_bcc_update COPY BYTES ENTER");
        cc_copy(bytes, state->bcc_scratch, _in);
        state->bcc_pos = bytes;
        cc_debug_log("df_bcc_update COPY BYTES EXIT");
    }
}

static void df_bcc_final(struct ccdrbg_nistctr_state *state)
{
    const uint8_t byte = 0x80;

    df_bcc_update(state, &byte, 1);

    if (state->bcc_pos) {
        /* if there's anything leftover... */
        size_t leftover = DRBG_STATE_BLOCK_SIZE(state) - state->bcc_pos;
        cc_memset((state->bcc_scratch + leftover), 0, leftover);
        bcc_update(state, state->bcc_scratch, 1, state->bcc_tmp);
    }
}

static ccdrbg_status_t block_cipher_df(struct ccdrbg_nistctr_state *state,
                                       const void *inputs[],
                                       size_t lengths[],
                                       size_t input_cnt,
                                       size_t nbytes_requested,
                                       void *output)
{
    uint64_t total_length = 0;
    uint32_t nblks = DRBG_BCC_STORAGE_BLOCKS_NUM(state);
    size_t output_blocks = nbytes_requested / DRBG_STATE_OUTLEN(state);
    uint8_t *tmp = state->bcc_tmp;
    uint8_t *x = &state->bcc_tmp[DRBG_STATE_KEY_LENGTH(state)];
    uint8_t buffer[64];
    ccctr_ctx_decl(state->ctr_mode->size, ctx);

    cc_clear(DRBG_BCC_STORAGE_SIZE(state), state->bcc_tmp);

    cc_debug_log("block_cipher_df: state %p", state);
    cc_debug_log("block_cipher_df: ins %p", inputs);
    cc_debug_log("block_cipher_df: lens %p", lengths);
    cc_debug_log("block_cipher_df: nbytes %zd", nbytes_requested);
    cc_debug_log("block_cipher_df: output %p", output);

    for (size_t i = 0; i < input_cnt; i++) {
        total_length += lengths[i];
    }

    if (nbytes_requested > 0xFFFFFFFF) {
        return CCDRBG_STATUS_OK;
    }

    for (size_t j = 0; j < DRBG_BCC_STORAGE_BLOCKS_NUM(state); j++) {
        cc_debug_log("block_cipher_df loop: %zd", j);
        cc_copy(DRBG_STATE_BLOCK_SIZE(state), state->bcc_tmp, state->bcc_initial_state);
        df_bcc_init(state, (uint32_t)total_length, nbytes_requested);

        for (size_t k = 0; k < input_cnt; k++) {
            cc_debug_log("block_cipher_df df_bcc_update: %p", inputs[k]);
            cc_debug_log("block_cipher_df df_bcc_update: %zd", lengths[k]);
            df_bcc_update(state, inputs[k], lengths[k]);
        }

        tmp += DRBG_STATE_OUTLEN(state);
    }

    ccctr_init(state->ctr_mode, ctx, DRBG_STATE_KEY_LENGTH(state), state->bcc_tmp, zeroes);
    if (nbytes_requested & (DRBG_STATE_OUTLEN(state) - 1)) {
        output_blocks++;
    }

    tmp = buffer;

    for (size_t l = 0; l < output_blocks; l++) {
        block_encrypt(DRBG_STATE_CTR_MODE(state), ctx, x, tmp);
        x = tmp;
        tmp += DRBG_STATE_OUTLEN(state);
    }

    cc_copy(nbytes_requested, output, buffer);
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, ctx);
    cc_clear(sizeof(buffer), buffer);
    cc_clear(DRBG_BCC_STORAGE_SIZE(state), state->bcc_tmp);

    return CCDRBG_STATUS_OK;
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
    uint32_t iv[MAX_BCC_STORAGE_SIZE];

    cc_clear(MAX_BCC_STORAGE_SIZE, iv);

    ccctr_init(state->ctr_mode, state->df_ctx, state->key_length, df_key, zeroes);

    /* Do the trick where we can precalc some of the components of the DF. */
    for (uint32_t i = 0; i < blks; i++) {
        iv[0] = cc_h2be32(i);
        bcc(state, iv, 1, &state->bcc_initial_state[i * DRBG_STATE_OUTLEN(state)]);
    }
}

CC_INLINE
ccdrbg_status_t are_parameters_valid(struct ccdrbg_nistctr_state *state,
                                     size_t ent_nbytes,
                                     size_t ad_nbytes,
                                     size_t ps_nbytes)
{
    ccdrbg_status_t status = CCDRBG_STATUS_OK;

    if (state->key_length > MAX_KEY_SIZE) {
        return CCDRBG_STATUS_PARAM_ERROR;
    }

    if (state->use_df) {
        if (ps_nbytes > CCDRBG_MAX_PSINPUT_SIZE) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
        if (ent_nbytes > CCDRBG_MAX_ENTROPY_SIZE) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
        if (ad_nbytes > CCDRBG_MAX_ADDITIONALINPUT_SIZE) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
        if (ent_nbytes < state->ctr_mode->ecb_block_size) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
    } else {
        if (ps_nbytes > DRBG_STATE_SEEDLEN(state)) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
        if (ent_nbytes != DRBG_STATE_BLOCK_SIZE(state)) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
        if (ad_nbytes > DRBG_STATE_SEEDLEN(state)) {
            status = CCDRBG_STATUS_PARAM_ERROR;
        }
    }

    return status;
}

#define __get_memory_offset(off) &(DRBG_STATE(state)->u[ccn_nof_size(ccn_sizeof_size(off))])

void ccdrbg_nistctr_update(struct ccdrbg_nistctr_state *state,
                           const uint8_t *in)
{
    uint8_t tmp[MAX_SEED_SIZE];

    cc_clear(MAX_SEED_SIZE, tmp);

    /* Use CTR since we have it. */
    ccctr_update(DRBG_STATE_CTR_MODE(state), DRBG_STATE_CTR_KEY(state), DRBG_STATE_SEEDLEN(state), zeroes, tmp);

    cc_xor(DRBG_STATE_SEEDLEN(state), tmp, tmp, in);
    cc_copy(DRBG_STATE_OUTLEN(state), state->V, (tmp + DRBG_STATE_KEY_LENGTH(state)));

    /* we need to accomodate for ourselves here. */
    inc_uint_be((state->V + (DRBG_STATE_OUTLEN(state) - COUNTER_LENGTH)), COUNTER_LENGTH);

    ccctr_init(DRBG_STATE_CTR_MODE(state), DRBG_STATE_CTR_KEY(state), DRBG_STATE_KEY_LENGTH(state), &tmp[0], &state->V[0]);

    cc_clear(MAX_SEED_SIZE, tmp);
}

ccdrbg_status_t ccdrbg_nistctr_init(const struct ccdrbg_info *info,
                                    struct ccdrbg_state *state,
                                    size_t entropy_length,
                                    const void *entropy,
                                    size_t nonce_length,
                                    const void *nonce,
                                    size_t ps_length,
                                    const void *ps)
{
    ccdrbg_status_t res = CCDRBG_STATUS_OK;
    struct ccdrbg_nistctr_state *_state = DRBG_STATE(state);
    const struct ccdrbg_nistctr_custom *_custom = (const struct ccdrbg_nistctr_custom *)info->custom;\
    uint8_t seed_material[MAX_SEED_SIZE];

    _state->ctr_mode = _custom->ctr;
    _state->key_length = _custom->key_length;
    _state->strictFIPS = _custom->strictFIPS;
    _state->use_df = _custom->use_df;

    cc_debug_log("drbg: ctr size %zd", _state->ctr_mode->size);
    cc_debug_log("drbg: ctr ecb block %zd", _state->ctr_mode->ecb_block_size);


    cc_debug_log("drbg: state ptr %p", state);
    _state->bcc_scratch = (uint8_t *)__get_memory_offset(0);
    cc_debug_log("drbg: bcc_scratch ptr %p", _state->bcc_scratch);
    _state->bcc_initial_state = (uint8_t *)__get_memory_offset(DRBG_STATE_OUTLEN(state));
    cc_debug_log("drbg: bcc_initial_state ptr %p", _state->bcc_initial_state);
    _state->bcc_tmp = (uint8_t *)__get_memory_offset((DRBG_BCC_STORAGE_SIZE(state) + DRBG_STATE_OUTLEN(state)));
    cc_debug_log("drbg: bcc_tmp ptr %p", _state->bcc_tmp);
    _state->ctr_ctx = (ccctr_ctx *)__get_memory_offset(((2 * DRBG_BCC_STORAGE_SIZE(state)) + DRBG_STATE_OUTLEN(state)));
    cc_debug_log("drbg: ctr_ctx ptr %p", _state->ctr_ctx);
    _state->df_ctx = (ccctr_ctx *)__get_memory_offset(((2 * DRBG_BCC_STORAGE_SIZE(state)) + DRBG_STATE_OUTLEN(state)) + DRBG_STATE_CTR_MODE(state)->size);
    cc_debug_log("drbg: df_ctx ptr %p", _state->df_ctx);

    res = are_parameters_valid(_state, entropy_length, 0, ps_length);
    if (res) {
        return res;
    }

    if (_state->use_df) {
        const void *ins[3];
        size_t lens[3];
        uint32_t cnt = 2;

        ins[0] = entropy;
        lens[0] = entropy_length;
        ins[1] = nonce;
        lens[1] = nonce_length;

        if (ps) {
            ins[2] = ps;
            lens[2] = ps_length;
            cnt++;
        }

        df_predf_init(_state);

        res = block_cipher_df(_state, ins, lens, cnt, DRBG_STATE_SEEDLEN(state), seed_material);
        if (res) {
            return res;
        }
    } else {
        cc_clear(MAX_SEED_SIZE, seed_material);
        if (ps && ps_length) {
            if (ps_length > sizeof(seed_material)) {
                return CCDRBG_STATUS_PARAM_ERROR;
            }

            cc_copy(ps_length, seed_material, ps);
            cc_xor(DRBG_STATE_SEEDLEN(state), seed_material, seed_material, entropy);
        }
    }

    /* make sure that our state is clean... */
    cc_clear(_state->key_length, _state->key);
    cc_clear(DRBG_STATE_OUTLEN(state), _state->V);

    _state->V[DRBG_STATE_OUTLEN(state)-1] = 1;

    ccctr_init(DRBG_STATE_CTR_MODE(state), DRBG_STATE_CTR_KEY(state), DRBG_STATE_KEY_LENGTH(state), _state->key, _state->V);
    ccdrbg_nistctr_update(_state, seed_material);
    cc_clear(sizeof(seed_material), seed_material);

    _state->reseed_counter = 1;

    return CCDRBG_STATUS_OK;
}

ccdrbg_status_t ccdrbg_nistctr_reseed(struct ccdrbg_state *state,
                                      size_t entropy_length,
                                      const void *entropy,
                                      size_t ad_length,
                                      const void *ad)
{
    ccdrbg_status_t stat = CCDRBG_STATUS_OK;
    uint8_t seed_material[MAX_SEED_SIZE];

    stat = are_parameters_valid(DRBG_STATE(state), entropy_length, ad_length, 0);
    if (stat) {
        return stat;
    }

    if (DRBG_STATE(state)->use_df) {
        const void *ins[2];
        size_t lens[2];
        uint32_t cnt = 1;

        ins[0] = entropy;
        lens[0] = entropy_length;

        if (ad) {
            ins[1] = ad;
            lens[1] = ad_length;
            cnt++;
        }

        stat = block_cipher_df(DRBG_STATE(state), ins, lens, cnt, DRBG_STATE_SEEDLEN(state), seed_material);
        if (stat) {
            return stat;
        }
    } else {
        cc_clear(MAX_SEED_SIZE, seed_material);
        if (ad && ad_length) {
            if (ad_length > sizeof(seed_material)) {
                return CCDRBG_STATUS_PARAM_ERROR;
            }

            cc_copy(ad_length, seed_material, ad);
            cc_xor(DRBG_STATE_SEEDLEN(state), seed_material, seed_material, entropy);
        }
    }

    ccdrbg_nistctr_update(DRBG_STATE(state), seed_material);
    DRBG_STATE(state)->reseed_counter = 1;

    stat = CCDRBG_STATUS_OK;

    return stat;
}

ccdrbg_status_t ensure_we_can_gen(struct ccdrbg_nistctr_state *state,
                                  size_t req_bytes,
                                  size_t ad_len)
{
    if (req_bytes > CCDRBG_MAX_REQUEST_SIZE) {
        return CCDRBG_STATUS_PARAM_ERROR;
    }

    if (state->use_df) {
        if (ad_len > CCDRBG_MAX_ADDITIONALINPUT_SIZE) {
            return CCDRBG_STATUS_PARAM_ERROR;
        }
    } else {
        if (ad_len > DRBG_STATE_SEEDLEN(state)) {
            return CCDRBG_STATUS_PARAM_ERROR;
        }
    }

    if ((state->reseed_counter > CCDRBG_RESEED_INTERVAL) && state->strictFIPS) {
        return CCDRBG_STATUS_NEED_RESEED;
    }

    return CCDRBG_STATUS_OK;
}

ccdrbg_status_t ccdrbg_nistctr_generate(struct ccdrbg_state *state,
                                        size_t out_length,
                                        void *out,
                                        size_t ad_length,
                                        const void *ad)
{
    ccdrbg_status_t stat = CCDRBG_STATUS_OK;
    uint8_t additional[MAX_SEED_SIZE];
    uint8_t leftover_out[MAX_BLOCK_SIZE];       /* We use this to get CTR to increment the counter... */
    uint8_t *_out = (uint8_t *)out;

    stat = ensure_we_can_gen(DRBG_STATE(state), out_length, ad_length);
    if (stat) {
        return stat;
    }

    if (ad && ad_length) {
        if (DRBG_STATE(state)->use_df) {
            const void *input[1];
            size_t len[1];

            input[0] = ad;
            len[0] = ad_length;

            stat = block_cipher_df(DRBG_STATE(state), input, len, 1, DRBG_STATE_SEEDLEN(state), additional);
            if (stat) {
                cc_clear(sizeof(additional), additional);
            }
        } else {
            cc_clear(sizeof(additional), additional);
            cc_copy(ad_length, additional, ad);
        }

		ccdrbg_nistctr_update(DRBG_STATE(state), additional);
    }

    while (out_length >= DRBG_STATE_OUTLEN(state)) {
        size_t nbytes = cc_min(DRBG_STATE_OUTLEN(state), out_length);
        ccctr_update(DRBG_STATE_CTR_MODE(state), DRBG_STATE_CTR_KEY(state), nbytes, zeroes, _out);
        out_length -= nbytes;
        _out += nbytes;
    }

    size_t leftover = (DRBG_STATE_OUTLEN(state) - out_length);
    /* check that leftover < outlen because we can end up here aligned on a block */
    if (leftover < DRBG_STATE_OUTLEN(state)) {
        ccctr_update(DRBG_STATE_CTR_MODE(state), DRBG_STATE_CTR_KEY(state), leftover, zeroes, leftover_out);
        cc_clear(leftover, leftover_out);
    }

    const uint8_t *dat;
    if (ad && ad_length) {
        dat = additional;
    } else {
        dat = zeroes;
    }

    ccdrbg_nistctr_update(DRBG_STATE(state), dat);

    DRBG_STATE(state)->reseed_counter++;

    cc_clear(sizeof(additional), additional);
    return CCDRBG_STATUS_OK;
}

void ccdrbg_nistctr_done(struct ccdrbg_state *state)
{
    cc_clear(DRBG_STATE_OUTLEN(state), DRBG_STATE(state)->bcc_scratch);
    cc_clear(DRBG_BCC_STORAGE_SIZE(state), DRBG_STATE(state)->bcc_initial_state);
    cc_clear(DRBG_BCC_STORAGE_SIZE(state), DRBG_STATE(state)->bcc_tmp);
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, DRBG_STATE_CTR_KEY(state));
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, DRBG_STATE_DF_KEY(state));
    cc_clear(sizeof(struct ccdrbg_nistctr_state), state);
}

void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom)
{
    info->size = DRBG_STATE_SIZE(custom);
    info->init = &ccdrbg_nistctr_init;
    info->reseed = &ccdrbg_nistctr_reseed;
    info->generate = &ccdrbg_nistctr_generate;
    info->done = &ccdrbg_nistctr_done;
    info->custom = custom;
}
