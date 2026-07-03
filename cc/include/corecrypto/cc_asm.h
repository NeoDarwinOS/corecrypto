/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_ASM_H__
#define __CORECRYPTO_CC_ASM_H__

#include <corecrypto/cc_config.h>

#if __ASSEMBLER__

#if CC_PLATFORM_DARWIN || CC_PLATFORM_XNU
    #define CC_ASM_SECTION_CONST    .const
    #define CC_ASM_PRIVATE_EXTERN   .private_extern
    #define CC_C_LABEL(sym)         _##sym
    #define CC_ASM_CONSTANT(c)      $##c
    #define CC_ALIGN(x) .align x
#elif CC_PLATFORM_LINUX
    #define CC_ASM_SECTION_CONST    .rodata
    #define CC_ASM_PRIVATE_EXTERN   .hidden
    #define CC_C_LABEL(sym)         sym
    #define CC_ASM_CONSTANT(c)      c
    #define CC_ALIGN(x) .p2align x
#endif

/*
* TODO: Convenience macros for reg save/restore
*/

#endif

#endif /* __CORECRYPTO_CC_ASM_H__ */
