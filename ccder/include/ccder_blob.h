/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCDER_BLOB_H__
#define __CORECRYPTO_CCDER_BLOB_H__

#include <corecrypto/ccasn1.h>

#define CCDER_MULTIBYTE_TAGS    1

#if CCDER_MULTIBYTE_TAGS
typedef unsigned long ccder_tag;
#else
typedef uint8_t ccder_tag;
#endif

struct ccder_blob {
    uint8_t *der_start;
    uint8_t *der_end;
};

struct ccder_read_blob {
    const uint8_t *der_start;
    const uint8_t *der_end;
};

#define CCDER_EOL               CCASN1_EOL
#define CCDER_BOOLEAN           CCASN1_BOOLEAN
#define CCDER_INTEGER           CCASN1_INTEGER
#define CCDER_BIT_STRING        CCASN1_BIT_STRING
#define CCDER_OCTET_STRING      CCASN1_OCTET_STRING
#define CCDER_NULL              CCASN1_NULL
#define CCDER_OBJECT_IDENTIFIER CCASN1_OBJECT_IDENTIFIER
#define CCDER_OBJECT_DESCRIPTOR CCASN1_OBJECT_DESCRIPTOR
#define CCDER_REAL              CCASN1_REAL
#define CCDER_ENUMERATED        CCASN1_ENUMERATED
#define CCDER_EMBEDDED_PDV      CCASN1_EMBEDDED_PDV
#define CCDER_UTF8_STRING       CCASN1_UTF8_STRING
#define CCDER_SEQUENCE          CCASN1_SEQUENCE
#define CCDER_SET               CCASN1_SET
#define CCDER_NUMERIC_STRING    CCASN1_NUMERIC_STRING
#define CCDER_PRINTABLE_STRING  CCASN1_PRINTABLE_STRING
#define CCDER_T61_STRING        CCASN1_T61_STRING
#define CCDER_VIDEOTEX_STRING   CCASN1_VIDEOTEX_STRING
#define CCDER_IA5_STRING        CCASN1_IA5_STRING
#define CCDER_UTC_TIME          CCASN1_UTC_TIME
#define CCDER_GENERALIZED_TIME  CCASN1_GENERALIZED_TIME
#define CCDER_GRAPHIC_STRING    CCASN1_GRAPHIC_STRING
#define CCDER_VISIBLE_STRING    CCASN1_VISIBLE_STRING
#define CCDER_GENERAL_STRING    CCASN1_GENERAL_STRING
#define CCDER_UNIVERSAL_STRING  CCASN1_UNIVERSAL_STRING
#define CCDER_BMP_STRING        CCASN1_BMP_STRING
#define CCDER_HIGH_TAG_NUMBER   CCASN1_HIGH_TAG_NUMBER
#define CCDER_TELETEX_STRING    CCDER_T61_STRING

#endif /* __CORECRYPTO_CCDER_BLOB_H__ */
