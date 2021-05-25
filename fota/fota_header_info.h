// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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

#ifndef __FOTA_HEADER_INFO_H_
#define __FOTA_HEADER_INFO_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_crypto_defs.h"
#include "fota/fota_component_defs.h"
#include "fota/fota_status.h"

#ifdef __cplusplus
extern "C" {
#endif

// These checks are only relevant when FOTA is enabled (unlike this header file)

#if !defined(MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION)
#error MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION expected to be set in fota_config.h
#endif

#if !defined(FOTA_HEADER_HAS_CANDIDATE_READY)
#error FOTA_HEADER_HAS_CANDIDATE_READY expected to be set in fota_config.h
#endif

#define FOTA_FW_HEADER_MAGIC ((uint32_t)(0x5c0253a3))

#define FOTA_CANDIDATE_READY_MAGIC ((uint32_t)(0xfed54e01))

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)
#define ARM_UC_HEADER_SIZE_V2_EXTERNAL             (296)
#define ARM_UC_HEADER_SIZE_V2_INTERNAL             (112)

#define ARM_UC_HEADER_MAGIC_V2_EXTERNAL            (0x5a51b3d4UL)
#define ARM_UC_HEADER_MAGIC_V2_INTERNAL            (0x5a51b3d4UL)
#endif

// Tells that we have a candidate ready
typedef struct {
    uint32_t magic;
    char comp_name[FOTA_COMPONENT_MAX_NAME_SIZE];
    uint32_t footer;
} fota_candidate_ready_header_t;

#define FOTA_HEADER_ENCRYPTED_FLAG               0x01
#define FOTA_HEADER_SUPPORT_RESUME_FLAG          0x02
#define FOTA_INTERNAL_HEADER_RESERVED_FIELD_SIZE 0x40

/*
 * FW header as found in flash.
 *
 * FW image is accompanied with header contaning image metadata.
 * The header is consumed by bootloader for verifying image integrity and by the Pelion FOTA
 * module for reporting current version details.
 */
typedef struct {
    uint32_t magic;                                     /*< Magic value */
    uint32_t fw_size;                                   /*< FW size in bytes */
    uint64_t version;                                   /*< FW version - timestamp */
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    uint8_t signature[FOTA_IMAGE_RAW_SIGNATURE_SIZE];   /*< RAW ECDSA signature */
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    uint8_t digest[FOTA_CRYPTO_HASH_SIZE];              /*< FW image SHA256 digest */
    uint8_t reserved[FOTA_INTERNAL_HEADER_RESERVED_FIELD_SIZE];    /*< Reserved */

    // From this point on, all fields are relevant to candidate only and
    // can be skipped by bootloader if it wishes not to save them internally
    // !The size of the internal header can't be changed, different size of the header 
    // will break older version of the bootloader.
    // reserved field should be used for additional internal header data.
    uint8_t internal_header_barrier;
    uint8_t flags;                                  /*< Flags */
    uint16_t external_header_size;                  /*< Size of external header size */
    uint16_t block_size;                            /*< Block size. Encryption block size if encrypted,
                                                        validated block size if unencrypted and block validation turned on */
    uint8_t precursor[FOTA_CRYPTO_HASH_SIZE];       /*< contains previously installed FW SHA256 digest */
    /*< Vendor custom data as received in Pelion FOTA manifest. */
    uint8_t vendor_data[FOTA_MANIFEST_VENDOR_DATA_SIZE];
#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)
    /*< Encrypted info to encrypt\decrypt payload Encryption key */
    uint8_t encrypted_fw_key[FOTA_ENCRYPT_KEY_SIZE];
    uint8_t encrypted_fw_key_tag[FOTA_ENCRYPT_TAG_SIZE];
    uint64_t encrypted_fw_key_iv;
#endif
    uint32_t footer;
    // !New fields of the external header must me added in the end of the current structure,
    // otherwise additional field will break older version of the bootloader.

} fota_header_info_t;

static inline size_t fota_get_header_size(void)
{
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    return ARM_UC_HEADER_SIZE_V2_EXTERNAL;
#else
    return ARM_UC_HEADER_SIZE_V2_INTERNAL;
#endif
#elif (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 3)
    return sizeof(fota_header_info_t);
#endif
}

static inline void fota_set_header_info_magic(fota_header_info_t *header_info)
{
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    header_info->magic = ARM_UC_HEADER_MAGIC_V2_EXTERNAL;
#else
    header_info->magic = ARM_UC_HEADER_MAGIC_V2_INTERNAL;
#endif
#elif (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 3)
    header_info->magic = FOTA_FW_HEADER_MAGIC;
    header_info->footer = FOTA_FW_HEADER_MAGIC;
#endif
}

int fota_deserialize_header(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info);
int fota_serialize_header(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size, size_t *header_buf_actual_size);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_HEADER_INFO_H_
