/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccsha2.h>

const struct ccdigest_info *ccsha224_di(void)
{
    return &ccsha224_ltc_di;
}

const struct ccdigest_info *ccsha256_di(void)
{
    return &ccsha256_ltc_di;
}

const struct ccdigest_info *ccsha384_di(void)
{
    return &ccsha384_ltc_di;
}

const struct ccdigest_info *ccsha512_di(void)
{
    return &ccsha512_ltc_di;
}

const struct ccdigest_info *ccsha512_224_di(void)
{
    return &ccsha512_224_ltc_di;
}

const struct ccdigest_info *ccsha512_256_di(void)
{
    return &ccsha512_256_ltc_di;
}
