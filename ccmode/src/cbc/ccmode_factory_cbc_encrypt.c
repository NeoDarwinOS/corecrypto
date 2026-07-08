/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc, const struct ccmode_ecb *ecb)
{
    cbc->size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) +
                ccn_sizeof_size(ecb->size);

    cbc->block_size = ccecb_block_size(ecb);
    cbc->init = &ccmode_cbc_init;
    cbc->cbc = &ccmode_cbc_encrypt;
    cbc->custom = ecb;

    cbc->impl_name = "factory";
}
