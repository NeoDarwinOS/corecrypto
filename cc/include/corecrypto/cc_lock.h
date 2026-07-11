/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_LOCK_H__
#define __CORECRYPTO_CC_LOCK_H__

#include <corecrypto/cc.h>

#if CC_PLATFORM_XNU
#include <kern/locks.h>

typedef struct cc_lock {
    lck_grp_t *lck_grp;
    lck_mtx_t *lck_mtx;
} cc_lock_t;

#elif CC_PLATFORM_DARWIN

#include <os/lock.h>

typedef struct cc_lock {
    struct os_unfair_lock_s lock;
} cc_lock_t;

#elif CC_PLATFORM_LINUX

#include <pthread.h>

typedef struct cc_lock {
    pthread_mutex_t mtx;
} cc_lock_t;

#endif

void cc_lock_init(cc_lock_t *lock, const char *group_name);
void cc_lock_lock(cc_lock_t *lock);
void cc_lock_unlock(cc_lock_t *lock);
bool cc_lock_try_lock(cc_lock_t *lock);

#endif /* __CORECRYPTO_CC_LOCK_H__ */
