/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCPOST_INTERNAL_H__
#define __CORECRYPTO_CCPOST_INTERNAL_H__

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccpost.h>

CC_PRIVATE
cc_error_t ccpost_aes_ecb_validate(void);

CC_PRIVATE
cc_error_t ccpost_aes_cbc_validate(void);

CC_PRIVATE
cc_error_t ccpost_aes_ctr_validate(void);

CC_PRIVATE
cc_error_t ccpost_ctr_drbg_validate(void);

#if CC_PLATFORM_XNU
#ifndef _FN_KPRINTF
#define _FN_KPRINTF
extern void kprintf(const char *fmt, ...) __printflike(1, 2);
#endif

#define cc_post_log(fmt, x...) kprintf("CCPOST: " fmt "\n", ##x)
#define cc_post_func_log(fmt, x...) kprintf("CCPOST [%s]: " fmt "\n", __FUNCTION__, ##x)
#define cc_post_func_hex_log(fmt, length, buffer) {     \
        kprintf("CCPOST [%s]: " fmt "\n", __FUNCTION__);\
        size_t len = length;                            \
        size_t i = 0;                                   \
        while (len--) {                                 \
            kprintf("%02x ", buffer[i]);                \
            i++;                                        \
                                                        \
            if ((len % 8) == 0) {                       \
                kprintf("\n");                          \
            }                                           \
        }                                               \
    }
#else
#include <stdio.h>

#if CC_PLATFORM_WINDOWS
#define cc_post_log(fmt, ...) printf("CCPOST: " fmt "\n", __VA_ARGS__)

#define cc_post_func_log(fmt, ...) printf("CCPOST [%s]: " fmt "\n", __FUNCTION__, __VA_ARGS__)
#else
#define cc_post_log(fmt, x...) printf("CCPOST: " fmt "\n", ##x)

#define cc_post_func_log(fmt, x...) printf("CCPOST [%s]: " fmt "\n", __FUNCTION__, ##x)
#endif

#define cc_post_func_hex_log(fmt, length, buffer) {     \
        printf("CCPOST [%s]: " fmt "\n", __FUNCTION__); \
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

#endif

#endif /* __CORECRYPTO_CCPOST_INTERNAL_H__ */
