/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_MEMORY_H__
#define __CORECRYPTO_CC_MEMORY_H__

#include <corecrypto/cc.h>

#if CC_PLATFORM_XNU
#include <IOKit/IOLib.h>

#define cc_heap_allocate(size) IOMalloc(size)
#define cc_heap_free(ptr, size) \
            IOFree(ptr, size); \
            cc_clear(size, ptr);
#else
#include <stdlib.h>

#define cc_heap_allocate(size) malloc(size)
#define cc_heap_free(ptr, size)     \
            cc_clear(size, ptr); \
            free(ptr);
#endif

#define cc_stack_allocate(size) __builtin_alloca(size)
#define cc_stack_free(ptr, size) cc_clear(size, ptr)

#if CC_ENABLE_HEAP_BACKED_WORKSPACES
#define cc_ws_buffer_allocate(size) cc_heap_allocate(size)
#define cc_ws_buffer_free(ptr, size) cc_heap_free(ptr, size)
#else
#define cc_ws_buffer_allocate(size) cc_stack_allocate(size)
#define cc_ws_buffer_free(ptr, size) cc_stack_free(ptr, size)
#endif

/* A workspace- any particular carveout region of memory for cryptographic API use. */
typedef struct cc_ws {
    cc_size capacity;
    cc_unit *region_begin;
    cc_unit *region_end;
} *cc_ws_t;

/* These macros are sensitive to overflowing. Do not use them directly. */
#define CC_WORKSPACE_PUSH(ws, units)    \
    ws->region_begin += units;          \
    ws->capacity -= units;

#define CC_WORKSPACE_POP(ws, units)     \
    ws->region_begin -= units;          \
    ws->capacity += units;

#define CC_WORKSPACE_DECL(name, units) \
    cc_unit *__##name##_buf = (cc_unit *)cc_ws_buffer_allocate(ccn_sizeof_n(units)); \
    struct cc_ws __##name##_struct_ws { units, __##name##_buf, (__##name##_buf + units) }; \
    cc_ws_t __##name##_ws = &__##name##_struct_ws;

#define CC_WORKSPACE_FREE(name, units)                      \
    cc_ws_buffer_free(__##name##_ws->region_begin, units);  \
    __##name##_ws->region_begin = NULL;                     \
    __##name##_ws->region_end = NULL;                       \
    __##name##_ws->capacity = 0;

CC_INLINE cc_unit *CC_WS_ALLOCATE(cc_ws_t ws, cc_size units)
{
    if (ws->capacity < units) {
        return NULL;
    } else {
        cc_unit *memory = ws->region_begin;
        CC_WORKSPACE_PUSH(ws, units);

        return memory;
    }
}

CC_INLINE void CC_WS_DEALLOCATE(cc_ws_t ws, cc_size units)
{
    CC_WORKSPACE_POP(ws, units);
}

#endif /* __CORECRYPTO_CC_MEMORY_H__ */
