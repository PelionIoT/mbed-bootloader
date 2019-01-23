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

#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"
#include "update-client-metadata-header/arm_uc_buffer_utilities.h"
#include <string.h>

extern arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key, arm_uc_buffer_t *input, arm_uc_buffer_t *output);

arm_uc_error_t ARM_UC_getDeviceKey256Bit(arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (output->size_max >= ARM_UC_DEVICE_KEY_SIZE) {
        int8_t rv = mbed_cloud_client_get_rot_128bit(output->ptr, output->size_max);
        if (rv == 0) {
            arm_uc_buffer_t input = {
                .size_max = ARM_UC_DEVICE_HMAC_KEY_SIZE,
                .size = ARM_UC_DEVICE_HMAC_KEY_SIZE,
                .ptr = (uint8_t *) &ARM_UC_DEVICE_HMAC_KEY
            };
            output->size = ARM_UC_ROT_SIZE;
#if defined(PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC) && \
    (PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC == 1)
            result = ARM_UC_cryptoHMACSHA256(&input, output, output);
#else
            result = ARM_UC_cryptoHMACSHA256(output, &input, output);
#endif
        }
    }

    if (result.code != ERR_NONE) {
        /* clear buffer on failure so we don't leak the rot */
        memset(output->ptr, 0, output->size_max);
    }

    return result;
}

arm_uc_error_t arm_uc_parse_internal_header_v2(const uint8_t *input,
                                               arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (input && details) {
        /* calculate CRC */
        uint32_t calculatedChecksum = arm_uc_crc32(input, ARM_UC_INTERNAL_HEADER_CRC_OFFSET_V2);

        /* read out CRC */
        uint32_t temp32 = arm_uc_parse_uint32(&input[ARM_UC_INTERNAL_HEADER_CRC_OFFSET_V2]);

        if (temp32 == calculatedChecksum) {
            /* parse content */
            details->version = arm_uc_parse_uint64(&input[ARM_UC_INTERNAL_FIRMWARE_VERSION_OFFSET_V2]);
            details->size = arm_uc_parse_uint64(&input[ARM_UC_INTERNAL_FIRMWARE_SIZE_OFFSET_V2]);

            memcpy(details->hash,
                   &input[ARM_UC_INTERNAL_FIRMWARE_HASH_OFFSET_V2],
                   ARM_UC_SHA256_SIZE);

            memcpy(details->campaign,
                   &input[ARM_UC_INTERNAL_CAMPAIGN_OFFSET_V2],
                   ARM_UC_GUID_SIZE);

            /* set result */
            result.code = ERR_NONE;
        }
    }

    return result;
}

arm_uc_error_t arm_uc_create_internal_header_v2(const arm_uc_firmware_details_t *input,
                                                arm_uc_buffer_t *output)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (input &&
            output &&
            (output->size_max >= ARM_UC_INTERNAL_HEADER_SIZE_V2)) {
        /* zero buffer */
        memset(output->ptr, 0, ARM_UC_INTERNAL_HEADER_SIZE_V2);

        /* MSB encode header magic and version */
        arm_uc_write_uint32(&output->ptr[0],
                            ARM_UC_INTERNAL_HEADER_MAGIC_V2);
        arm_uc_write_uint32(&output->ptr[4],
                            ARM_UC_INTERNAL_HEADER_VERSION_V2);

        /* MSB encode firmware version */
        arm_uc_write_uint64(&output->ptr[ARM_UC_INTERNAL_FIRMWARE_VERSION_OFFSET_V2],
                            input->version);

        /* MSB encode firmware size to header */
        arm_uc_write_uint64(&output->ptr[ARM_UC_INTERNAL_FIRMWARE_SIZE_OFFSET_V2],
                            input->size);

        /* raw copy firmware hash to header */
        memcpy(&output->ptr[ARM_UC_INTERNAL_FIRMWARE_HASH_OFFSET_V2],
               input->hash,
               ARM_UC_SHA256_SIZE);

        /* raw copy campaign ID to header */
        memcpy(&output->ptr[ARM_UC_INTERNAL_CAMPAIGN_OFFSET_V2],
               input->campaign,
               ARM_UC_GUID_SIZE);

        /* calculate CRC */
        uint32_t checksum = arm_uc_crc32(output->ptr,
                                         ARM_UC_INTERNAL_HEADER_CRC_OFFSET_V2);

        /* MSB encode checksum to header */
        arm_uc_write_uint32(&output->ptr[ARM_UC_INTERNAL_HEADER_CRC_OFFSET_V2],
                            checksum);

        /* set output size */
        output->size = ARM_UC_INTERNAL_HEADER_SIZE_V2;

        /* set error code */
        result.code = ERR_NONE;
    }

    return result;
}

arm_uc_error_t arm_uc_parse_external_header_v2(const uint8_t *input,
                                               arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (input && details) {

        /* read 128 bit root-of-trust */
        uint8_t key_buf[ARM_UC_DEVICE_KEY_SIZE] = { 0 };
        arm_uc_buffer_t key = {
            .size_max = ARM_UC_DEVICE_KEY_SIZE,
            .size = 0,
            .ptr = key_buf
        };
        arm_uc_error_t status = ARM_UC_getDeviceKey256Bit(&key);

        if (status.error == ERR_NONE) {
            arm_uc_buffer_t input_buf = {
                .size_max = ARM_UC_EXTERNAL_HMAC_OFFSET_V2,
                .size = ARM_UC_EXTERNAL_HMAC_OFFSET_V2,
                .ptr = (uint8_t *) input
            };
            arm_uc_hash_t hmac = { 0 };
            arm_uc_buffer_t output_buf = {
                .size_max = sizeof(arm_uc_hash_t),
                .size = sizeof(arm_uc_hash_t),
                .ptr = (uint8_t *) &hmac
            };

            /* calculate header HMAC */
            status = ARM_UC_cryptoHMACSHA256(&key, &input_buf, &output_buf);

            if (status.error == ERR_NONE) {
                input_buf.size_max = sizeof(arm_uc_hash_t);
                input_buf.size = sizeof(arm_uc_hash_t);
                input_buf.ptr = (uint8_t *) &input[ARM_UC_EXTERNAL_HMAC_OFFSET_V2];

                int diff = ARM_UC_BinCompareCT(&input_buf, &output_buf);

                if (diff == 0) {
                    details->version = arm_uc_parse_uint64(&input[ARM_UC_EXTERNAL_FIRMWARE_VERSION_OFFSET_V2]);
                    details->size = arm_uc_parse_uint64(&input[ARM_UC_EXTERNAL_FIRMWARE_SIZE_OFFSET_V2]);

                    memcpy(details->hash,
                           &input[ARM_UC_EXTERNAL_FIRMWARE_HASH_OFFSET_V2],
                           ARM_UC_SHA256_SIZE);

                    memcpy(details->campaign,
                           &input[ARM_UC_EXTERNAL_CAMPAIGN_OFFSET_V2],
                           ARM_UC_GUID_SIZE);

                    details->signatureSize = 0;

                    result.code = ERR_NONE;
                }
            }
        }
    }

    return result;
}

arm_uc_error_t arm_uc_create_external_header_v2(const arm_uc_firmware_details_t *input,
                                                arm_uc_buffer_t *output)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (input &&
            output &&
            (output->size_max >= ARM_UC_EXTERNAL_HEADER_SIZE_V2)) {
        /* zero buffer and reset size*/
        memset(output->ptr, 0, ARM_UC_EXTERNAL_HEADER_SIZE_V2);
        output->size = 0;

        /* MSB encode header magic and version */
        arm_uc_write_uint32(&output->ptr[0],
                            ARM_UC_EXTERNAL_HEADER_MAGIC_V2);
        arm_uc_write_uint32(&output->ptr[4],
                            ARM_UC_EXTERNAL_HEADER_VERSION_V2);

        /* MSB encode firmware version */
        arm_uc_write_uint64(&output->ptr[ARM_UC_EXTERNAL_FIRMWARE_VERSION_OFFSET_V2],
                            input->version);

        /* MSB encode firmware size to header */
        arm_uc_write_uint64(&output->ptr[ARM_UC_EXTERNAL_FIRMWARE_SIZE_OFFSET_V2],
                            input->size);

        /* raw copy firmware hash to header */
        memcpy(&output->ptr[ARM_UC_EXTERNAL_FIRMWARE_HASH_OFFSET_V2],
               input->hash,
               ARM_UC_SHA256_SIZE);

        /* MSB encode payload size to header */
        arm_uc_write_uint64(&output->ptr[ARM_UC_EXTERNAL_PAYLOAD_SIZE_OFFSET_V2],
                            input->size);

        /* raw copy payload hash to header */
        memcpy(&output->ptr[ARM_UC_EXTERNAL_PAYLOAD_HASH_OFFSET_V2],
               input->hash,
               ARM_UC_SHA256_SIZE);

        /* raw copy campaign ID to header */
        memcpy(&output->ptr[ARM_UC_EXTERNAL_CAMPAIGN_OFFSET_V2],
               input->campaign,
               ARM_UC_GUID_SIZE);

        /* read 256 bit device key */
        uint8_t key_buf[ARM_UC_DEVICE_KEY_SIZE] = { 0 };
        arm_uc_buffer_t key = {
            .size_max = ARM_UC_DEVICE_KEY_SIZE,
            .size = 0,
            .ptr = key_buf
        };

        arm_uc_error_t status = ARM_UC_getDeviceKey256Bit(&key);

        if (status.error == ERR_NONE) {
            arm_uc_buffer_t input_buf = {
                .size_max = ARM_UC_EXTERNAL_HMAC_OFFSET_V2,
                .size = ARM_UC_EXTERNAL_HMAC_OFFSET_V2,
                .ptr = output->ptr
            };
            arm_uc_buffer_t output_buf = {
                .size_max = sizeof(arm_uc_hash_t),
                .size = sizeof(arm_uc_hash_t),
                .ptr = &output->ptr[ARM_UC_EXTERNAL_HMAC_OFFSET_V2]
            };

            /* calculate header HMAC */
            result = ARM_UC_cryptoHMACSHA256(&key, &input_buf, &output_buf);
            if (result.error == ERR_NONE) {
                /* set output size */
                output->size = ARM_UC_EXTERNAL_HEADER_SIZE_V2;
            }
        }
    }

    return result;
}
