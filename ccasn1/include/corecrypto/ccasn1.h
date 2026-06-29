/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCASN1_H__
#define __CORECRYPTO_CCASN1_H__

#include <corecrypto/cc.h>

#define CCASN1_EOL                  0x00
#define CCASN1_BOOLEAN              0x01
#define CCASN1_INTEGER              0x02
#define CCASN1_BIT_STRING           0x03
#define CCASN1_OCTET_STRING         0x04
#define CCASN1_NULL                 0x05
#define CCASN1_OBJECT_IDENTIFIER    0x06
#define CCASN1_OBJECT_DESCRIPTOR    0x07
#define CCASN1_REAL                 0x09
#define CCASN1_ENUMERATED           0x0A
#define CCASN1_EMBEDDED_PDV         0x0B
#define CCASN1_UTF8_STRING          0x0C
#define CCASN1_SEQUENCE             0x10
#define CCASN1_SET                  0x11
#define CCASN1_NUMERIC_STRING       0x12
#define CCASN1_PRINTABLE_STRING     0x13
#define CCASN1_T61_STRING           0x14
#define CCASN1_VIDEOTEX_STRING      0x15
#define CCASN1_IA5_STRING           0x16
#define CCASN1_UTC_TIME             0x17
#define CCASN1_GENERALIZED_TIME     0x18
#define CCASN1_GRAPHIC_STRING       0x19
#define CCASN1_VISIBLE_STRING       0x1A
#define CCASN1_GENERAL_STRING       0x1B
#define CCASN1_UNIVERSAL_STRING     0x1C
#define CCASN1_BMP_STRING           0x1E
#define CCASN1_HIGH_TAG_NUMBER      0x1F

#define CCASN1_TAG_MASK             0xFF
#define CCASN1_TAGNUM_MASK          0x1F

#define CCASN1_METHOD_MASK          0x20
#define CCASN1_PRIMITIVE            0x00
#define CCASN1_CONSTRUCTED          0x20

#define CCASN1_CLASS_MASK           0xC0
#define CCASN1_UNIVERSAL            0x00
#define CCASN1_APPLICATION          0x40
#define CCASN1_CONTEXT_SPECIFIC     0x80
#define CCASN1_PRIVATE              0xC0

#define CCASN1_TELETAX_STRING       CCASN1_T61_STRING

#define CCASN1_CONSTRUCTED_SET      CCASN1_SET | CCASN1_CONSTRUCTED
#define CCASN1_CONSTRUCTED_SEQUENCE CCASN1_SEQUENCE | CCASN1_CONSTRUCTED

/*!
 * @typedef ccoid_t
 *          A DER encoded Object Identifier.
 */
typedef const uint8_t *ccoid_t;

#define CCOID(oid) ((ccoid_t)oid)

CC_PURE CC_NONNULL((1, 2))
bool ccoid_equal(ccoid_t oid1, ccoid_t oid2);

CC_PURE CC_NONNULL((1))
size_t ccoid_size(ccoid_t oid);

#endif /* __CORECRYPTO_CCASN1_H__ */
