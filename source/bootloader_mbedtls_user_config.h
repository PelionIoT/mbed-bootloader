// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/* System support */
#define MBEDTLS_HAVE_ASM

#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_CIPHER_MODE_CTR

#undef MBEDTLS_SHA512_C
#undef MBEDTLS_MD5_C
#undef MBEDTLS_MD4_C
#undef MBEDTLS_SHA1_C

// Remove RSA, save 20KB at total
#undef MBEDTLS_RSA_C
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

// Remove error messages, save 10KB of ROM
#undef MBEDTLS_ERROR_C

// Remove selftesting and save 11KB of ROM
#undef MBEDTLS_SELF_TEST

// Reduces ROM size by 30 kB
#undef MBEDTLS_ERROR_STRERROR_DUMMY
#undef MBEDTLS_VERSION_FEATURES
#undef MBEDTLS_DEBUG_C

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CUSTOM_CONFIG_H */
