/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_lock.h>

#if CC_PLATFORM_XNU

/* HACK: public sdk doesnt define lck_mtx_try_lock */
#if !defined(GATE_HANDOFF)
extern boolean_t lck_mtx_try_lock(lck_mtx_t *lck);
#endif

void cc_lock_init(cc_lock_t *lock, const char *group_name)
{
    lock->lck_grp = lck_grp_alloc_init(group_name, NULL);
    lock->lck_mtx = lck_mtx_alloc_init(lock->lck_grp, NULL);
}

void cc_lock_lock(cc_lock_t *lock)
{
    lck_mtx_lock(lock->lck_mtx);
}

void cc_lock_unlock(cc_lock_t *lock)
{
    lck_mtx_unlock(lock->lck_mtx);
}

bool cc_lock_try_lock(cc_lock_t *lock)
{
    return lck_mtx_try_lock(lock->lck_mtx);
}

#elif CC_PLATFORM_DARWIN

void cc_lock_init(cc_lock_t *lock, const char *group_name)
{
    lock->lock = OS_UNFAIR_LOCK_INIT;
}

void cc_lock_lock(cc_lock_t *lock)
{
    os_unfair_lock_lock(&lock->lock);
}

void cc_lock_unlock(cc_lock_t *lock)
{
    os_unfair_lock_unlock(&lock->lock);
}

bool cc_lock_try_lock(cc_lock_t *lock)
{
    return os_unfair_lock_trylock(&lock->lock);
}

#elif CC_PLATFORM_LINUX

void cc_lock_init(cc_lock_t *lock, const char *group_name)
{
    pthread_mutex_init(&lock->mtx, NULL);
}

void cc_lock_lock(cc_lock_t *lock)
{
    pthread_mutex_lock(&lock->mtx);
}

void cc_lock_unlock(cc_lock_t *lock)
{
    pthread_mutex_unlock(&lock->mtx);
}

bool cc_lock_try_lock(cc_lock_t *lock)
{
    return pthread_mutex_trylock(&lock->mtx);
}

#endif
