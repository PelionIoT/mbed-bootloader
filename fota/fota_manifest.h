// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
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

#ifndef __FOTA_MANIFEST_H_
#define __FOTA_MANIFEST_H_

#include "fota/fota_base.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FOTA_MANIFEST_DEBUG
#define FOTA_MANIFEST_TRACE_DEBUG FOTA_TRACE_DEBUG
#else
#define FOTA_MANIFEST_TRACE_DEBUG(fmt, ...)
#endif

#define FOTA_MANIFEST_PAYLOAD_FORMAT_RAW    1
#define FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA  5

/*
 * Update details as extracted from the Pelion FOTA manifest
 */
typedef struct {
    uint64_t       version;                                      /*< FW version (timestamp). */
    uint32_t       priority;                                     /*< Update priority. */
    uint32_t       payload_format;                               /*< Payload format. */
    uint32_t       payload_size;                                 /*< Payload size to be downloaded. */
    uint32_t       installed_size;                               /*< Installed FW size. In case payload_format equals FOTA_MANIFEST_PAYLOAD_FORMAT_RAW  the value is equal to payload_size. */
    uint8_t        payload_digest[FOTA_CRYPTO_HASH_SIZE];        /*< Payload SHA226 digest - for verifying downloaded payload integrity. */
    char           uri[FOTA_MANIFEST_URI_SIZE];                  /*< Payload URI for downloading the payload. */
    uint8_t        installed_digest[FOTA_CRYPTO_HASH_SIZE];      /*< Installed FW SHA256 digest. In case payload_format equals FOTA_MANIFEST_PAYLOAD_FORMAT_RAW  the value is equal to payload_digest. */
    uint8_t        precursor_digest[FOTA_CRYPTO_HASH_SIZE];      /*< Currently installed (before update) FW SHA256 digest.*/
    char           component_name[FOTA_COMPONENT_MAX_NAME_SIZE]; /*< Component name */
    uint8_t        vendor_data[FOTA_MANIFEST_VENDOR_DATA_SIZE];  /*< Vendor custom data as received in Pelion FOTA manifest. */
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    uint8_t        installed_signature[FOTA_IMAGE_RAW_SIGNATURE_SIZE]; /** Raw encoded signature over installed image */
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)

} manifest_firmware_info_t;

/*
 * Parse and validate Pelion FOTA manifest.
 *
 * Parse ASN.1 DER encoded manifest and assert it is suitable for current device.
 *
 * \param[in]  manifest_buf      Pionter to a buffer holding Pelion FOTA manifest to be parsed
 * \param[in]  manifest_size     Input manifest size
 * \param[out] fw_info           Pointer to a struct holding update details
 * \param[in]  current_fw_digest Currently installed FW SHA256 digest - required for asserting precursor digest
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_manifest_parse(
    const uint8_t *manifest_buf,
    size_t manifest_size,
    manifest_firmware_info_t *fw_info);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_MANIFEST_H_
