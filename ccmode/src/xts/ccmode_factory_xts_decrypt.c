/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

void ccmode_factory_xts_decrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt) {
    xts->size = ccn_sizeof_size(ecb->size) +
                ccn_sizeof_size(ecb_encrypt->size) +
                ccn_sizeof_size(sizeof(struct _ccmode_xts_key));
    
    xts->tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) +
                      ccn_sizeof_size(ecb_encrypt->block_size);
    
    xts->init = &ccmode_xts_init;
    xts->key_sched = &ccmode_xts_key_sched;
    xts->set_tweak = &ccmode_xts_set_tweak;
    xts->xts = &ccmode_xts_crypt;
    
    xts->custom = ecb;
    xts->custom1 = ecb_encrypt;
}
