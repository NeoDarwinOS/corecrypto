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
#include <corecrypto/cc_priv.h>

/*
 *  FOR DEVELOPMENT: I'm going to be VERY careful with this library and force DEBUG builds to crash on ANY misuse of APIs.
 *
 *  DEBUG builds are for debugging after all.
 */
#define cc_internal_crash(cond, msg) if (!!(cond)) { cc_abort("BUG IN CORECRYPTO: " msg); }
#define cc_client_crash(cond, msg) if (!!(cond)) { cc_abort("BUG IN CLIENT OF CORECRYPTO: " msg); }

#if CORECRYPTO_DEBUG
    #define cc_debug_abort(cond, msg, code) cc_internal_crash(cond, msg)
    #define cc_debug_client_abort(cond, msg, code) cc_client_crash(cond, msg)
#else
    #define cc_debug_abort(cond, msg, code) if (!!(cond)) { return code; }
    #define cc_debug_client_abort(cond, msg, code) if (!!(cond)) { return code; }
#endif

#if CC_PLATFORM_XNU
#include <pexpert/pexpert.h>

#define cc_debug_log(fmt, x...) kprintf("corecrypto: " fmt "\n", ##x)
#else
#include <stdio.h>

#define cc_debug_log(fmt, x...) printf("corecrypto: " fmt "\n", ##x)
#endif

#endif /* __CORECRYPTO_CC_DEBUG_H__ */
