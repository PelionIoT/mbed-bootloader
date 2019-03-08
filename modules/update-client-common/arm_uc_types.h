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

#ifndef ARM_UPDATE_COMMON_TYPES_H
#define ARM_UPDATE_COMMON_TYPES_H

#include <stdint.h>

typedef struct {
    uint32_t size_max; // maximum size of the buffer
    uint32_t size;     // index of the first empty byte in the buffer
    uint8_t *ptr;      // pointer to buffer's memory
} arm_uc_buffer_t;

#define ARM_UC_GUID_SIZE       (128/8)
#define ARM_UC_SHA256_SIZE     (256/8)
#define ARM_UC_SHA512_SIZE     (512/8)
#define ARM_UC_AES256_KEY_SIZE (256/8)
#define ARM_UC_AES_BLOCK_SIZE  (128/8)
#define ARM_UC_ROT_SIZE        (128/8)
#define ARM_UC_DEVICE_KEY_SIZE (256/8)

#define ARM_UC_DEVICE_HMAC_KEY "StorageEnc256HMACSHA256SIGNATURE"
#define ARM_UC_DEVICE_HMAC_KEY_SIZE (sizeof(ARM_UC_DEVICE_HMAC_KEY) - 1)

/**
 * @brief GUID type
 */
typedef uint8_t arm_uc_guid_t[ARM_UC_GUID_SIZE];

/**
 * @brief SHA256 hash
 */
typedef uint8_t arm_uc_hash_t[ARM_UC_SHA256_SIZE];

/**
 * @brief Firmware details struct.
 * @details Struct for passing information between the Update client and the
 *          PAAL implementation describing the firmware image.
 */
typedef struct _arm_uc_firmware_details_t {
    uint64_t version;
    uint64_t size;
    arm_uc_hash_t hash;
    arm_uc_guid_t campaign;
    uint32_t signatureSize;
    uint8_t signature[0];
} arm_uc_firmware_details_t;

/**
 * @brief Installer details struct.
 * @details Struct for reading the installer information.
 */
typedef struct _arm_uc_installer_details_t {
    arm_uc_hash_t arm_hash;
    arm_uc_hash_t oem_hash;
    uint32_t layout;
} arm_uc_installer_details_t;

#endif // ARM_UPDATE_COMMON_TYPES_H
