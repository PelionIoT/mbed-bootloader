// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef __FOTA_CONFIG_H_
#define __FOTA_CONFIG_H_

#if !defined(FOTA_UNIT_TEST)

// skip this include in Bootloader and unittest builds as the configurations are delivered by other means
#include "MbedCloudClientConfig.h"

#else  // external configuration - unit tests

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR)
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR 0
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE (1)
#endif

#endif // defined(FOTA_UNIT_TEST)

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#ifndef MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE
#error Block device type must be defined
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE) || (MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE == 0)
#error Storage size should be defined and have a nonzero value
#endif

#if !defined(FOTA_MANIFEST_SCHEMA_VERSION)
#define FOTA_MANIFEST_SCHEMA_VERSION        3
#endif

#if !defined(FOTA_MANIFEST_URI_SIZE)
#define FOTA_MANIFEST_URI_SIZE            256
#endif

#if !defined(FOTA_MANIFEST_VENDOR_DATA_SIZE)
#define FOTA_MANIFEST_VENDOR_DATA_SIZE    0
#endif

#if !defined(FOTA_CERT_MAX_SIZE)
#define FOTA_CERT_MAX_SIZE 600
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE 1024
#endif

#if !(FOTA_MANIFEST_SCHEMA_VERSION == 1)
// Mainfest schema version #1 requires public key in  x509 form
// Other cases require defaults to uncompressed elliptic curve
//  point format (X9.62)
#define FOTA_USE_UPDATE_RAW_PUBLIC_KEY
#else
#define FOTA_USE_UPDATE_X509
#endif

#if (FOTA_MANIFEST_SCHEMA_VERSION < 3)
#define FOTA_SOURCE_LEGACY_OBJECTS_REPORT 1

#if !defined(FOTA_MANIFEST_MAX_SIZE)
#define FOTA_MANIFEST_MAX_SIZE           650
#endif

#else  // (FOTA_MANIFEST_SCHEMA_VERSION < 3)
#define FOTA_SOURCE_LEGACY_OBJECTS_REPORT 0
#endif  // (FOTA_MANIFEST_SCHEMA_VERSION < 3)

#if !defined(FOTA_MANIFEST_MAX_SIZE)
#define FOTA_MANIFEST_MAX_SIZE           580
#endif

#define FOTA_RESUME_UNSUPPORTED     0
#define FOTA_RESUME_SUPPORT_RESTART 1
#define FOTA_RESUME_SUPPORT_RESUME  2

#define FOTA_INTERNAL_FLASH_BD      1
#define FOTA_CUSTOM_BD              2
#define FOTA_EXTERNAL_BD            3

#ifndef MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT
#define MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT FOTA_RESUME_SUPPORT_RESUME
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION)
#define MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION 3
#endif

#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE != FOTA_EXTERNAL_BD)
#ifndef __MBED__
#error This type of block device is only supported in mbed-os
#endif
#endif

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)

#define FOTA_HEADER_HAS_CANDIDATE_READY 1

#if !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)
// set candidate encryption flag to false by default for internal flash
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_BD)
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 0
#else
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 1
#endif
#endif

#else  // LEGACY profile (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)

#define FOTA_HEADER_HAS_CANDIDATE_READY 0

#if !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 0
#elif (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
#error MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT enabled only for header version >= 3
#endif // !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
// force resume restart for legacy profile
#undef MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT
#define MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT FOTA_RESUME_SUPPORT_RESTART
#endif

#endif  // (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE

#endif  // __FOTA_CONFIG_H_
