// ----------------------------------------------------------------------------
// Copyright 2021 Pelion.
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
#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)

#include "fota/fota_status.h"
#include "fota/fota_header_info.h"
#include "fota/fota_crypto.h"
#include "mbedtls/md.h"
#include "CloudClientStorage.h"

#define ARM_UC_HEADER_VERSION_V2          (2)
#define ARM_UC_HEADER_VERSION_OFFSET_V2   (4)
#define ARM_UC_FIRMWARE_VERSION_OFFSET_V2 (8)
#define ARM_UC_FIRMWARE_SIZE_OFFSET_V2    (16)
#define ARM_UC_FIRMWARE_HASH_OFFSET_V2    (24)

#define ARM_UC_PAYLOAD_SIZE_OFFSET_V2_EXTERNAL     (88)
#define ARM_UC_PAYLOAD_HASH_OFFSET_V2_EXTERNAL     (96)
#define ARM_UC_CAMPAIGN_OFFSET_V2_EXTERNAL         (160)
#define ARM_UC_HMAC_OFFSET_V2_EXTERNAL             (232)
#define ARM_UC_HEADER_SIZE_V2_EXTERNAL             (296)

#define ARM_UC_CAMPAIGN_OFFSET_V2_INTERNAL         (88)
#define ARM_UC_SIGNATURE_SIZE_OFFSET_V2_INTERNAL   (104)
#define ARM_UC_HEADER_CRC_OFFSET_V2_INTERNAL       (108)
#define ARM_UC_HEADER_SIZE_V2_INTERNAL             (112)


#define ARM_UC_AES256_KEY_SIZE (256/8)
#define ARM_UC_AES_BLOCK_SIZE  (128/8)
#define ARM_UC_ROT_SIZE        (128/8)
#define ARM_UC_DEVICE_KEY_SIZE (256/8)
#define ARM_UC_GUID_SIZE       (128/8)

#define ARM_UC_DEVICE_HMAC_KEY "StorageEnc256HMACSHA256SIGNATURE"
#define ARM_UC_DEVICE_HMAC_KEY_SIZE (sizeof(ARM_UC_DEVICE_HMAC_KEY) - 1)


#ifdef __MBED__
#include "KVMap.h"
#include "TDBStore.h"
using namespace mbed;
#endif

#ifdef __cplusplus
extern "C" {
#endif

size_t arm_uc_crc32(const uint8_t *buffer, size_t length)
{
    const uint8_t *current = buffer;
    size_t crc = 0xFFFFFFFF;

    while (length--) {
        crc ^= *current++;

        for (size_t counter = 0; counter < 8; counter++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }

    return (crc ^ 0xFFFFFFFF);
}

void arm_uc_write_uint32(uint8_t *buffer, size_t value)
{
    if (buffer) {
        buffer[3] = value;
        buffer[2] = (value >> 8);
        buffer[1] = (value >> 16);
        buffer[0] = (value >> 24);
    }
}

size_t arm_uc_parse_uint32(const uint8_t *input)
{
    size_t result = 0;

    if (input) {
        result = input[0];
        result = (result << 8) | input[1];
        result = (result << 8) | input[2];
        result = (result << 8) | input[3];
    }

    return result;
}

void arm_uc_write_uint64(uint8_t *buffer, uint64_t value)
{
    if (buffer) {
        buffer[7] = value;
        buffer[6] = (value >> 8);
        buffer[5] = (value >> 16);
        buffer[4] = (value >> 24);
        buffer[3] = (value >> 32);
        buffer[2] = (value >> 40);
        buffer[1] = (value >> 48);
        buffer[0] = (value >> 56);
    }
}

uint64_t arm_uc_parse_uint64(const uint8_t *input)
{
    uint64_t result = 0;

    if (input) {
        result = input[0];
        result = (result << 8) | input[1];
        result = (result << 8) | input[2];
        result = (result << 8) | input[3];
        result = (result << 8) | input[4];
        result = (result << 8) | input[5];
        result = (result << 8) | input[6];
        result = (result << 8) | input[7];
    }

    return result;
}

static int fota_hmac_sha256(const uint8_t *key, size_t key_size,
                            const uint8_t *message, size_t message_size,
                            uint8_t output[ARM_UC_DEVICE_KEY_SIZE])
{
    int ret = FOTA_STATUS_INTERNAL_ERROR;

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, key_size, message, message_size, output) == 0) {
        ret = FOTA_STATUS_SUCCESS;
    }

    return ret;
}

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)

#ifdef __MBED__
static int mbed_cloud_client_get_rot_128bit(uint8_t * key, size_t keyLenBytes)
{
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);


    //Check key buffer
    if (key == NULL) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    //Check key buffer size
    if (keyLenBytes != ARM_UC_ROT_SIZE) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    //Check internal instance 
    if (inner_store == NULL) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    //Read ROT
    int error = ((TDBStore *)inner_store)->reserved_data_get(key, keyLenBytes);
    if (error != 0) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;

}
#endif

static int fota_get_device_key_256Bit(uint8_t key_buf_hmac[ARM_UC_DEVICE_KEY_SIZE])
{
    int ret = FOTA_STATUS_INTERNAL_ERROR;

#ifdef __MBED__
    ret = mbed_cloud_client_get_rot_128bit(key_buf_hmac, ARM_UC_ROT_SIZE);
#else
    ret = FOTA_STATUS_SUCCESS;
    memset(key_buf_hmac, 0x27, ARM_UC_ROT_SIZE);
#endif
    if (ret) {
        return ret;
    }

    ret  = fota_hmac_sha256(key_buf_hmac, ARM_UC_ROT_SIZE,
                            (const uint8_t *) &ARM_UC_DEVICE_HMAC_KEY,
                            ARM_UC_DEVICE_HMAC_KEY_SIZE,
                            key_buf_hmac);
    return ret;
}

static int serialize_header_v2_external(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size)
{
    memset(header_buf, 0, ARM_UC_HEADER_SIZE_V2_EXTERNAL);

    /* MSB encode header magic and version */
    arm_uc_write_uint32(header_buf,
                        ARM_UC_HEADER_MAGIC_V2_EXTERNAL);

    arm_uc_write_uint32(header_buf + ARM_UC_HEADER_VERSION_OFFSET_V2,
                        ARM_UC_HEADER_VERSION_V2);

    /* MSB encode firmware version */
    arm_uc_write_uint64(header_buf + ARM_UC_FIRMWARE_VERSION_OFFSET_V2,
                        header_info->version);

    /* MSB encode firmware size to header */
    arm_uc_write_uint64(header_buf + ARM_UC_FIRMWARE_SIZE_OFFSET_V2,
                        header_info->fw_size);

    /* raw copy firmware hash to header */
    memcpy(header_buf + ARM_UC_FIRMWARE_HASH_OFFSET_V2,
           header_info->digest,
           FOTA_CRYPTO_HASH_SIZE);

    /* raw copy campaign ID to header */
    memset(header_buf + ARM_UC_CAMPAIGN_OFFSET_V2_INTERNAL,
           0,
           ARM_UC_GUID_SIZE);

    /* MSB encode payload size to header */
    arm_uc_write_uint64(header_buf + ARM_UC_PAYLOAD_SIZE_OFFSET_V2_EXTERNAL,
                        header_info->fw_size);

    /* raw copy payload hash to header */
    memcpy(header_buf + ARM_UC_PAYLOAD_HASH_OFFSET_V2_EXTERNAL,
           header_info->digest,
           FOTA_CRYPTO_HASH_SIZE);

    /* read 256 bit device key */
    uint8_t key_buf_hmac[ARM_UC_DEVICE_KEY_SIZE] = { 0 };
    int ret = fota_get_device_key_256Bit(key_buf_hmac);
    if (ret) {
        return ret;
    }

    ret  = fota_hmac_sha256(key_buf_hmac, ARM_UC_DEVICE_KEY_SIZE,
                            (const uint8_t *) header_buf, ARM_UC_HMAC_OFFSET_V2_EXTERNAL,
                            (header_buf + ARM_UC_HMAC_OFFSET_V2_EXTERNAL));
    if (ret) {
        return ret;
    }

    return FOTA_STATUS_SUCCESS;
}

#else

static int serialize_header_v2_internal(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size)
{
    memset(header_buf, 0, ARM_UC_HEADER_SIZE_V2_INTERNAL);

    /* MSB encode header magic and version */
    arm_uc_write_uint32(header_buf,
                        ARM_UC_HEADER_MAGIC_V2_INTERNAL);

    arm_uc_write_uint32(header_buf + ARM_UC_HEADER_VERSION_OFFSET_V2,
                        ARM_UC_HEADER_VERSION_V2);

    /* MSB encode firmware version */
    arm_uc_write_uint64(header_buf + ARM_UC_FIRMWARE_VERSION_OFFSET_V2,
                        header_info->version);

    /* MSB encode firmware size to header */
    arm_uc_write_uint64(header_buf + ARM_UC_FIRMWARE_SIZE_OFFSET_V2,
                        header_info->fw_size);

    /* raw copy firmware hash to header */
    memcpy(header_buf + ARM_UC_FIRMWARE_HASH_OFFSET_V2,
           header_info->digest,
           FOTA_CRYPTO_HASH_SIZE);

    /* raw copy campaign ID to header */
    memset(header_buf + ARM_UC_CAMPAIGN_OFFSET_V2_INTERNAL,
           0,
           ARM_UC_GUID_SIZE);

    /* calculate CRC */
    size_t checksum = arm_uc_crc32(header_buf,
                                   ARM_UC_HEADER_CRC_OFFSET_V2_INTERNAL);

    /* MSB encode checksum to header */
    arm_uc_write_uint32(header_buf + ARM_UC_HEADER_CRC_OFFSET_V2_INTERNAL,
                        checksum);

    return FOTA_STATUS_SUCCESS;
}

#endif

int fota_serialize_header(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size, size_t *header_buf_actual_size)
{
    FOTA_DBG_ASSERT(fota_get_header_size() <= header_buf_size);

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    *header_buf_actual_size = ARM_UC_HEADER_SIZE_V2_EXTERNAL;
    return serialize_header_v2_external(header_info, header_buf, header_buf_size);
#else
    *header_buf_actual_size = ARM_UC_HEADER_SIZE_V2_INTERNAL;
    return serialize_header_v2_internal(header_info, header_buf, header_buf_size);
#endif
}

#ifdef FOTA_COMPLETE_TEST

static int deserialize_header_v2_external(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info)
{
    FOTA_DBG_ASSERT(fota_get_header_size() <= buffer_size);
    memset(header_info, 0, sizeof(*header_info));

    header_info->magic = arm_uc_parse_uint32(buffer);
    if (header_info->magic != ARM_UC_HEADER_MAGIC_V2_EXTERNAL) {
        FOTA_TRACE_ERROR("Invalid header in current installed firmware");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    header_info->version = arm_uc_parse_uint64(buffer + ARM_UC_FIRMWARE_VERSION_OFFSET_V2);
    header_info->fw_size = (size_t)arm_uc_parse_uint64(buffer + ARM_UC_FIRMWARE_SIZE_OFFSET_V2);

    memcpy(header_info->digest,
           buffer + ARM_UC_FIRMWARE_HASH_OFFSET_V2,
           FOTA_CRYPTO_HASH_SIZE);

    return FOTA_STATUS_SUCCESS;
}

#endif

static int deserialize_header_v2_internal(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info)
{
    FOTA_DBG_ASSERT(fota_get_header_size() <= buffer_size);
    memset(header_info, 0, sizeof(*header_info));

    header_info->magic = arm_uc_parse_uint32(buffer);
    if (header_info->magic != ARM_UC_HEADER_MAGIC_V2_INTERNAL) {
        FOTA_TRACE_ERROR("Invalid header in current installed firmware");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    /* calculate CRC */
    size_t calculatedChecksum = arm_uc_crc32(buffer, ARM_UC_HEADER_CRC_OFFSET_V2_INTERNAL);

    /* read out CRC */
    size_t temp32 = arm_uc_parse_uint32(buffer + ARM_UC_HEADER_CRC_OFFSET_V2_INTERNAL);

    if (temp32 == calculatedChecksum) {
        /* parse content */
        header_info->version = arm_uc_parse_uint64(buffer + ARM_UC_FIRMWARE_VERSION_OFFSET_V2);
        header_info->fw_size = (size_t)arm_uc_parse_uint64(buffer + ARM_UC_FIRMWARE_SIZE_OFFSET_V2);

        memcpy(header_info->digest,
               buffer + ARM_UC_FIRMWARE_HASH_OFFSET_V2,
               FOTA_CRYPTO_HASH_SIZE);

        return FOTA_STATUS_SUCCESS;
    }

    return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
}

int fota_deserialize_header(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info)
{
#ifdef FOTA_COMPLETE_TEST
    /* for unitests*/
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    return deserialize_header_v2_external(buffer, buffer_size, header_info);
#else
    return deserialize_header_v2_internal(buffer, buffer_size, header_info);
#endif

#else
    return deserialize_header_v2_internal(buffer, buffer_size, header_info);

#endif

}

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2 

#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
