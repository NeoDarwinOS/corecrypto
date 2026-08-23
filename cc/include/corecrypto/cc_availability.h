/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_AVAILABILITY_H__
#define __CORECRYPTO_CC_AVAILABILITY_H__

#include <corecrypto/cc_compatibility.h>

// TODO: switch to __API_AVAILABLE?
#if __has_include(<os/availability.h>) && !KERNEL
    #include <os/availability.h>
#endif

#if defined (API_AVAILABLE) && !KERNEL
#define CORECRYPTO_API_AVAILABLE_2012   \
        API_AVAILABLE(                  \
            macos(10.8),                \
            ios(6.0)                    \
        )

#define CORECRYPTO_API_AVAILABLE_2013   \
        API_AVAILABLE(                  \
            macos(10.9),                \
            ios(7.0)                    \
        )

#define CORECRYPTO_API_AVAILABLE_2014   \
        API_AVAILABLE(                  \
            macos(10.10),               \
            ios(8.0),                   \
            watchos(1.0)                \
        )

#define CORECRYPTO_API_AVAILABLE_FALL_2015  \
        API_AVAILABLE(                      \
            macos(10.11),                   \
            ios(9.0),                       \
            watchos(2.0),                   \
            tvos(9.0)                       \
        )

#define CORECRYPTO_API_AVAILABLE_FALL_2016  \
        API_AVAILABLE(                      \
            macos(10.12),                   \
            ios(10.0),                      \
            watchos(3.0),                   \
            tvos(10.0)                      \
        )

#define CORECRYPTO_API_AVAILABLE_FALL_2017  \
        API_AVAILABLE(                      \
            macos(10.13),                   \
            ios(11.0),                      \
            watchos(4.0),                   \
            tvos(11.0),                     \
            bridgeos(2.0)                   \
        )

#define CORECRYPTO_API_AVAILABLE_FALL_2018  \
        API_AVAILABLE(                      \
            macos(10.14),                   \
            ios(12.0),                      \
            watchos(5.0),                   \
            tvos(12.0),                     \
            bridgeos(3.0),                  \
        )

#define CORECRYPTO_API_AVAILABLE_FALL_2019  \
        API_AVAILABLE(                      \
            macos(10.15),                   \
            ios(13.0),                      \
            watchos(6.0),                   \
            tvos(13.0),                     \
            bridgeos(4.0)                   \
        )
#else
    #define CORECRYPTO_API_AVAILABLE_2012
    #define CORECRYPTO_API_AVAILABLE_2013
    #define CORECRYPTO_API_AVAILABLE_2014
    #define CORECRYPTO_API_AVAILABLE_FALL_2015
    #define CORECRYPTO_API_AVAILABLE_FALL_2016
    #define CORECRYPTO_API_AVAILABLE_FALL_2017
    #define CORECRYPTO_API_AVAILABLE_FALL_2018
    #define CORECRYPTO_API_AVAILABLE_FALL_2019
#endif

#endif /* __CORECRYPTO_CC_AVAILABILITY_H__ */
