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

#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_error.h"
#include <string.h>

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_CRYPTO_MBEDTLS) && (ARM_UC_FEATURE_CRYPTO_MBEDTLS == 1)
#include "mbedtls/md_internal.h"

arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key,
                                       arm_uc_buffer_t *input,
                                       arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info != NULL) {
        int8_t rv = mbedtls_md_hmac(md_info,
                                    key->ptr, key->size,
                                    input->ptr, input->size,
                                    output->ptr);
        if (rv == 0) {
            output->size = ARM_UC_SHA256_SIZE;
            result = (arm_uc_error_t) { ERR_NONE };
        }
    }

    return result;
}

#endif
