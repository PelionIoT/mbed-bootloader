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
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#define ARM_UC_SHA256_INTERNAL_BLOCK_SIZE (64)
#define ARM_UC_MBEDTLS_SUCCESS (0)
#define ARM_UC_MBEDTLS_FAILURE (-1)

/**
 * @brief      SHA256 specific implementation of mbedtls_md_hmac.
 *
 *             mbedtls_md_hmac supports multiple hash functions and serves as
 *             a MAC wrapper on top of the normal hash functions. This generality
 *             adds overhead in the form of wrapper code and reliance on dynamic
 *             memory.
 *
 *             The following function implements the same HMAC algorithm as
 *             mbedtls (see https://en.wikipedia.org/wiki/HMAC), except it
 *             won't accept a secret key larger than the block size (64 bytes).
 *
 *             In mbedtls_md_hmac, keys larger than the block size are reduced
 *             using the hash function. In ARM_UC_cryptoHMACSHA256 an error
 *             is returned instead.
 *
 *             The secret key is XOR'ed onto an inner and outer pad of the same
 *             size as the internal block size (64 bytes), which are then
 *             digested before and after the actual message:
 *
 *             hmac = sha256(outer_pad + sha256(inner_pad + message))
 *
 *             Note: ARM_UC_SHA256_INTERNAL_BLOCK_SIZE is the internal block size
 *             of 64 bytes while ARM_UC_SHA256_SIZE is the size of the actual
 *             hash, 32 bytes.
 *
 * @param      key     ARM UC buffer pointer to the secret key.
 * @param      input   ARM UC buffer pointer to the message.
 * @param      output  ARM UC buffer pointer to the hmac.
 *
 * @return     ARM UC return code.
 *             ERR_NONE on success.
 *             ARM_UC_CU_ERR_INVALID_PARAMETER on failure.
 */
arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key,
                                       arm_uc_buffer_t *input,
                                       arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) {
        ARM_UC_CU_ERR_INVALID_PARAMETER
    };

    if (key && key->ptr &&
            (key->size <= ARM_UC_SHA256_INTERNAL_BLOCK_SIZE) &&
            input && input->ptr &&
            output && output->ptr &&
            (output->size_max >= ARM_UC_SHA256_SIZE)) {

        int retval = ARM_UC_MBEDTLS_FAILURE;

        /**
         * HMAC pads the message with the key at both the beginning and the end.
         * Setup both pads immediately in case key and output points to the same
         * buffer.
         */
        uint8_t inner_pad[ARM_UC_SHA256_INTERNAL_BLOCK_SIZE];
        uint8_t outer_pad[ARM_UC_SHA256_INTERNAL_BLOCK_SIZE];

        memset(inner_pad, 0x36, ARM_UC_SHA256_INTERNAL_BLOCK_SIZE);
        memset(outer_pad, 0x5C, ARM_UC_SHA256_INTERNAL_BLOCK_SIZE);

        /* Inner/outer pad is the key XOR'ed with 0x36/0x5C.
        */
        for (size_t index = 0; index < key->size; index++) {
            inner_pad[index] = inner_pad[index] ^ key->ptr[index];
            outer_pad[index] = outer_pad[index] ^ key->ptr[index];
        }

        /* initialize hashing facility */
        mbedtls_sha256_context mbedtls_ctx;
        mbedtls_sha256_init(&mbedtls_ctx);

        /**
         * Inner pad.
         */
        retval = mbedtls_sha256_starts_ret(&mbedtls_ctx, 0);

        if (retval == ARM_UC_MBEDTLS_SUCCESS) {

            /* digest inner key */
            retval = mbedtls_sha256_update_ret(&mbedtls_ctx, inner_pad, ARM_UC_SHA256_INTERNAL_BLOCK_SIZE);

            if (retval == ARM_UC_MBEDTLS_SUCCESS) {

                /* digest message */
                retval = mbedtls_sha256_update_ret(&mbedtls_ctx, input->ptr, input->size);

                if (retval == ARM_UC_MBEDTLS_SUCCESS) {

                    /* finalize inner hash */
                    retval = mbedtls_sha256_finish_ret(&mbedtls_ctx, output->ptr);
                }
            }
        }

        /**
         * Outer pad.
         */
        if (retval == ARM_UC_MBEDTLS_SUCCESS) {

            retval = mbedtls_sha256_starts_ret(&mbedtls_ctx, 0);

            if (retval == ARM_UC_MBEDTLS_SUCCESS) {

                /* digest outer key */
                retval = mbedtls_sha256_update_ret(&mbedtls_ctx, outer_pad, ARM_UC_SHA256_INTERNAL_BLOCK_SIZE);

                if (retval == ARM_UC_MBEDTLS_SUCCESS) {

                    /* digest inner hash */
                    retval = mbedtls_sha256_update_ret(&mbedtls_ctx, output->ptr, ARM_UC_SHA256_SIZE);


                    if (retval == ARM_UC_MBEDTLS_SUCCESS) {

                        /* finalize outer hash */
                        retval = mbedtls_sha256_finish_ret(&mbedtls_ctx, output->ptr);

                        if (retval == ARM_UC_MBEDTLS_SUCCESS) {

                            output->size = ARM_UC_SHA256_SIZE;

                            result = (arm_uc_error_t) {
                                ERR_NONE
                            };
                        }
                    }
                }
            }
        }

        /* clean up */
        mbedtls_sha256_free(&mbedtls_ctx);
        mbedtls_platform_zeroize(inner_pad, ARM_UC_SHA256_INTERNAL_BLOCK_SIZE);
        mbedtls_platform_zeroize(outer_pad, ARM_UC_SHA256_INTERNAL_BLOCK_SIZE);
    }

    return result;
}

#endif
