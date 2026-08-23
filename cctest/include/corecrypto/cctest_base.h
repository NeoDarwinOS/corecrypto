/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCTEST_BASE_H__
#define __CORECRYPTO_CCTEST_BASE_H__

#include <corecrypto/cc.h>

enum cctest_log_level {
    CCTEST_LOG_ERROR = 1,
    CCTEST_LOG_WARNING,
    CCTEST_LOG_DEBUG,
};

struct cctest_vtable {
    void (*log)(enum cctest_log_level lvl, const char *fmt, ...);
};

struct cctest_base {
    const char *test_name;

    cc_error_t (*run)(const struct cctest_base *self);
    const void *custom;
};

cc_error_t cctest_run(const struct cctest_base *test);

/* useful for many applications */
uint8_t *cctest_hex_string_to_data(const char *str);
size_t cctest_hex_string_to_data_len(const char *str);

#endif /* __CORECRYPTO_CCTEST_BASE_H__ */
