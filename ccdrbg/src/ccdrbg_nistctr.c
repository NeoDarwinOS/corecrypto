/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "corecrypto/cc.h"
#include "corecrypto/cc_debug.h"
#include "corecrypto/ccmode.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/ccn.h>

#define cc_drbg_func_hex_log(fmt, length, buffer) {     \
        printf("ccdrbg [%s]: " fmt "\n", __FUNCTION__); \
        size_t len = length;                            \
        size_t i = 0;                                   \
        while (len--) {                                 \
            printf("%02x ", buffer[i]);                 \
            i++;                                        \
                                                        \
            if ((len % 8) == 0) {                       \
                printf("\n");                           \
            }                                           \
        }                                               \
    }


#define DRBG_STATE(x) ((struct ccdrbg_nistctr_state *)x)
#define DRBG_STATE_CTR_MODE(x) DRBG_STATE(x)->ctr_mode
#define DRBG_STATE_KEY_LENGTH(x) DRBG_STATE(x)->key_length
#define DRBG_STATE_BLOCK_SIZE(x) DRBG_STATE_CTR_MODE(x)->ecb_block_size

#define DRBG_STATE_CTR_KEY(x) DRBG_STATE(x)->ctr_ctx
#define DRBG_STATE_DF_KEY(x) DRBG_STATE(x)->df_ctx

#define DRBG_STATE_KEY(x) DRBG_STATE(x)->key
#define DRBG_STATE_V(x) DRBG_STATE(x)->V

#define DRBG_STATE_OUTLEN(x) DRBG_STATE_BLOCK_SIZE(x)

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

    ccdrbg_df_ctx_t *df;

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

static uint8_t zeroes[MAX_SEED_SIZE] = {0};

//
// break this operation up so that we can 
//
CC_INLINE
void init_ctr_key(struct ccdrbg_nistctr_state *state, ccctr_ctx *ctx)
{
    inc_uint_be(state->V + (DRBG_STATE_BLOCK_SIZE(state) - COUNTER_LENGTH), COUNTER_LENGTH);
    ccctr_init(DRBG_STATE_CTR_MODE(state), ctx, DRBG_STATE_KEY_LENGTH(state), DRBG_STATE_KEY(state), DRBG_STATE_V(state));
}

CC_INLINE
void update_internal_fields(struct ccdrbg_nistctr_state *state, ccctr_ctx *key, const uint8_t *in)
{
    ccctr_update(DRBG_STATE_CTR_MODE(state), key, DRBG_STATE_KEY_LENGTH(state), in, DRBG_STATE_KEY(state));
    in += DRBG_STATE_KEY_LENGTH(state);
    ccctr_update(DRBG_STATE_CTR_MODE(state), key, DRBG_STATE_BLOCK_SIZE(state), in, DRBG_STATE_V(state));
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

    if (state->df) {
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
        if (ent_nbytes != DRBG_STATE_SEEDLEN(state)) {
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
    ccctr_ctx_decl(ccctr_context_size(DRBG_STATE_CTR_MODE(state)), ctr);

    init_ctr_key(state, ctr);
    update_internal_fields(state, ctr, in);

    ccctr_ctx_clear(ccctr_context_size(DRBG_STATE_CTR_MODE(state)), ctr);
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
    _state->df = _custom->df_ctx;

    _state->bcc_scratch = (uint8_t *)__get_memory_offset(0);
    _state->bcc_initial_state = (uint8_t *)__get_memory_offset(DRBG_STATE_OUTLEN(state));
    _state->bcc_tmp = (uint8_t *)__get_memory_offset((DRBG_BCC_STORAGE_SIZE(state) + DRBG_STATE_OUTLEN(state)));
    _state->ctr_ctx = (ccctr_ctx *)__get_memory_offset(((2 * DRBG_BCC_STORAGE_SIZE(state)) + DRBG_STATE_OUTLEN(state)));
    _state->df_ctx = (ccctr_ctx *)__get_memory_offset(((2 * DRBG_BCC_STORAGE_SIZE(state)) + DRBG_STATE_OUTLEN(state)) + DRBG_STATE_CTR_MODE(state)->size);

    //
    // ensure a clean state
    //
    cc_clear(DRBG_STATE_OUTLEN(state), DRBG_STATE(state)->bcc_scratch);
    cc_clear(DRBG_BCC_STORAGE_SIZE(state), DRBG_STATE(state)->bcc_initial_state);
    cc_clear(DRBG_BCC_STORAGE_SIZE(state), DRBG_STATE(state)->bcc_tmp);
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, DRBG_STATE_CTR_KEY(state));
    ccctr_ctx_clear(DRBG_STATE_CTR_MODE(state)->size, DRBG_STATE_DF_KEY(state));

    res = are_parameters_valid(_state, entropy_length, 0, ps_length);
    if (res) {
        return res;
    }

    if (_state->df) {
        cc_iovec_t v[3] = {
            [0] = {entropy, entropy_length},
            [1] = {nonce, nonce_length},
            [2] = {ps, ps_length}
        };

        res = _state->df->derive_keys(_state->df, 3, v, DRBG_STATE_SEEDLEN(state), seed_material);
        if (res != CCERR_OK) {
            return res;
        }
    } else {
        cc_clear(MAX_SEED_SIZE, seed_material);
        if (ps && ps_length) {
            if (ps_length > sizeof(seed_material)) {
                return CCDRBG_STATUS_PARAM_ERROR;
            }

            cc_copy(entropy_length, seed_material, entropy);
            cc_xor(ps_length, seed_material, seed_material, ps);
        }
    }

    //cc_drbg_func_hex_log("seed material", sizeof(seed_material), seed_material);

    /* make sure that our state is clean... */
    cc_clear(_state->key_length, _state->key);
    cc_clear(DRBG_STATE_OUTLEN(state), _state->V);

    //_state->V[DRBG_STATE_OUTLEN(state)-1] = 1;

    //ccctr_init(DRBG_STATE_CTR_MODE(state), DRBG_STATE_CTR_KEY(state), DRBG_STATE_KEY_LENGTH(state), _state->key, _state->V);
    ccdrbg_nistctr_update(_state, seed_material);
    cc_clear(sizeof(seed_material), seed_material);

    //cc_drbg_func_hex_log("V:", DRBG_STATE_BLOCK_SIZE(state), DRBG_STATE_V(state));
    //cc_drbg_func_hex_log("Key:", DRBG_STATE_KEY_LENGTH(state), DRBG_STATE_KEY(state));

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

    if (DRBG_STATE(state)->df) {
        cc_iovec_t v[2] = {
            [0] = {entropy, entropy_length},
            [1] = {ad, ad_length},
        };

        stat = DRBG_STATE(state)->df->derive_keys(DRBG_STATE(state)->df, 2, v, DRBG_STATE_SEEDLEN(state), seed_material);
        if (stat != CCERR_OK) {
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

    //cc_drbg_func_hex_log("V:", DRBG_STATE_BLOCK_SIZE(state), DRBG_STATE_V(state));
    //cc_drbg_func_hex_log("Key:", DRBG_STATE_KEY_LENGTH(state), DRBG_STATE_KEY(state));

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

    if (state->df) {
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
    ccctr_ctx_decl(ccctr_context_size(DRBG_STATE_CTR_MODE(state)), ctr);

    stat = ensure_we_can_gen(DRBG_STATE(state), out_length, ad_length);
    if (stat) {
        return stat;
    }

    if (ad && ad_length) {
        if (DRBG_STATE(state)->df) {
            cc_iovec_t v[1] = {ad, ad_length};

            stat = DRBG_STATE(state)->df->derive_keys(DRBG_STATE(state)->df, 1, v, DRBG_STATE_SEEDLEN(state), additional);
            if (stat) {
                cc_clear(sizeof(additional), additional);
            }
        } else {
            cc_clear(sizeof(additional), additional);
            cc_copy(ad_length, additional, ad);
        }

		ccdrbg_nistctr_update(DRBG_STATE(state), additional);
    }

    //
    // tricks and hacks because we've rewriten the drbg
    //
    init_ctr_key(DRBG_STATE(state), ctr);

    while (out_length >= DRBG_STATE_OUTLEN(state)) {
        size_t nbytes = cc_min(DRBG_STATE_OUTLEN(state), out_length);
        ccctr_update(DRBG_STATE_CTR_MODE(state), ctr, nbytes, zeroes, _out);
        out_length -= nbytes;
        _out += nbytes;
    }

    size_t leftover = (DRBG_STATE_OUTLEN(state) - out_length);
    /* check that leftover < outlen because we can end up here aligned on a block */
    if (leftover < DRBG_STATE_OUTLEN(state)) {
        ccctr_update(DRBG_STATE_CTR_MODE(state), ctr, leftover, zeroes, leftover_out);
        cc_clear(leftover, leftover_out);
    }

    const uint8_t *dat;
    if (ad && ad_length) {
        dat = additional;
    } else {
        dat = zeroes;
    }

    update_internal_fields(DRBG_STATE(state), ctr, dat);
    ccctr_ctx_clear(ccctr_context_size(DRBG_STATE_CTR_MODE(state)), ctr);

    DRBG_STATE(state)->reseed_counter++;

    //cc_drbg_func_hex_log("V:", DRBG_STATE_BLOCK_SIZE(state), DRBG_STATE_V(state));
    //cc_drbg_func_hex_log("Key:", DRBG_STATE_KEY_LENGTH(state), DRBG_STATE_KEY(state));

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
