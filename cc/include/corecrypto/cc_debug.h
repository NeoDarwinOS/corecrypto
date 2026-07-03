/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_DEBUG_H__
#define __CORECRYPTO_CC_DEBUG_H__

#include <corecrypto/cc.h>

#if CORECRYPTO_DEBUG
    #define cc_debug_abort(cond, msg, code) if (!!(cond)) { cc_abort(msg); }
#else
    #define cc_debug_abort(cond, msg, code) if (!!(cond)) { return code; }
#endif

#if CC_PLATFORM_XNU
#include <pexpert/pexpert.h>

#define cc_debug_log(fmt, x...) kprintf("corecrypto: " fmt "\n", #x)
#else
#include <stdlib.h>

#define cc_debug_log(fmt, x...) printf("corecrypto: " fmt "\n", #x)
#endif

#endif /* __CORECRYPTO_CC_DEBUG_H__ */
