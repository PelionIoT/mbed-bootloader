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
#include "fota/fota_crypto_asn_extra.h"
#include "mbedtls/asn1.h"
#include <stdint.h>

int mbedtls_asn1_get_enumerated_value(unsigned char **p,
                                      const unsigned char *end,
                                      int *val)
{
    int ret;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_ENUMERATED)) != 0) {
        return (ret);
    }

    if (len == 0 || len > sizeof(int) || (**p & 0x80) != 0) {
        return (MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    *val = 0;

    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return (0);
}

int mbedtls_asn1_get_int64(unsigned char **p,
                           const unsigned char *end,
                           int64_t *val)
{
    int ret;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
        return (ret);
    }

    if (len == 0 || len > sizeof(int64_t) || (**p & 0x80) != 0) {
        return (MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    *val = 0;

    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return (0);
}
