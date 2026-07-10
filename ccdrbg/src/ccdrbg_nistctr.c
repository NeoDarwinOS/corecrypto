/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode.h>

#define DRBG_STATE(x) ((struct ccdrbg_nistctr_state *)x)
#define DRBG_CTR_MODE(x) DRBG_STATE(x)->custom.ctr

#define MAX_KEY_SIZE    CCAES_KEY_SIZE_256
#define MAX_BLOCK_SIZE  CCAES_BLOCK_SIZE
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


void ccdrbg_nistctr_done(struct ccdrbg_state *state)
{
    cc_clear(sizeof(struct ccdrbg_nistctr_state), state);
}
