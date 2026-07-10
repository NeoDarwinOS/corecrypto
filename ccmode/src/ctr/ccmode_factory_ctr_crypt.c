/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

void ccmode_factory_ctr_crypt(struct ccmode_ctr *ctr, const struct ccmode_ecb *ecb)
{
    ctr->size = ccn_sizeof_size(sizeof(struct _ccmode_ctr_key)) +
                ccn_sizeof_size(ecb->size) + ccn_sizeof_size(ecb->block_size * 2);

    ctr->ecb_block_size = ccecb_block_size(ecb);
    ctr->init = &ccmode_ctr_init;
    ctr->setctr = &ccmode_ctr_setctr;
    ctr->ctr = &ccmode_ctr_crypt;
    ctr->custom = ecb;

    ctr->impl_name = "factory";
}
