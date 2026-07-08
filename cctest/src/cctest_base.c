/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/cc_memory.h>
#include <corecrypto/cctest_base.h>

size_t cctest_hex_string_to_data_len(const char *str)
{
    return (strlen(str) / 2);
}

uint8_t cctest_hex_byte_to_nibble(uint8_t byte)
{
    if (byte >= '0' && byte <= '9') return byte - '0';
	if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
	if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;

	return 255;
}

uint8_t *cctest_hex_string_to_data(const char *str)
{
    size_t i = 0;
    size_t len = strlen(str);
    uint8_t *buf = (uint8_t *)cc_heap_allocate(cctest_hex_string_to_data_len(str));

    /* zerofill */

    /* just in case... */
    if (str == NULL) {
        str = "";
    }

    /* if the string length somehow isn't a multiple of two, do this. */
    if ((len & 1) && len != 0) {
        buf[i++] = cctest_hex_byte_to_nibble(*(str));
        len -= 1;
        str++;
    }

    while (len -= 2) {
        buf[i] = cctest_hex_byte_to_nibble(*str) << 4 | cctest_hex_byte_to_nibble(*(str+1));
        str += 2;
        i++;
    }

    return buf;
}
