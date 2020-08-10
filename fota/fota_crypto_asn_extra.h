// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#ifndef __FOTA_CRYPTO_ASN_EXTRA_H_
#define __FOTA_CRYPTO_ASN_EXTRA_H_

#include <stdint.h>

#define MBEDTLS_ASN1_ENUMERATED              0x0A

int mbedtls_asn1_get_enumerated_value(unsigned char **p,
                                      const unsigned char *end,
                                      int *val);
int mbedtls_asn1_get_int64(unsigned char **p,
                           const unsigned char *end,
                           int64_t *val);

#endif  // __FOTA_CRYPTO_ASN_EXTRA_H_
