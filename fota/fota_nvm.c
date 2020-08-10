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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_status.h"
#include "fota/fota_nvm.h"
#include "fota/fota_nvm_int.h"
#include "fota/fota_crypto.h"
#include "fota/fota_component.h"
#include "fota/fota_crypto_defs.h"
#include "mbed_error.h"
#include "mbed-trace/mbed_trace.h"
#include <stdlib.h>

static fota_status_e map_store_result(int result)
{
    fota_status_e res = FOTA_STATUS_INTERNAL_ERROR;

    switch (result) {
        case CCS_STATUS_SUCCESS:
            res = FOTA_STATUS_SUCCESS;
            break;
        case CCS_STATUS_MEMORY_ERROR:
            res = FOTA_STATUS_INSUFFICIENT_STORAGE;
            break;
        case CCS_STATUS_KEY_DOESNT_EXIST:
            res = FOTA_STATUS_NOT_FOUND;
            break;
        case CCS_STATUS_VALIDATION_FAIL:
        case CCS_STATUS_ERROR:
            break;
    }

    return res;
}

int fota_nvm_get(cloud_client_param key, uint8_t *buffer, size_t buffer_size, size_t *bytes_read)
{
    ccs_status_e result = get_config_parameter(key, buffer, buffer_size, bytes_read);
    return map_store_result(result);
}

int fota_nvm_set(cloud_client_param key, const uint8_t *buffer, size_t buffer_size)
{
    ccs_status_e result = set_config_parameter(key, buffer, buffer_size);
    return map_store_result(result);
}

int fota_nvm_remove(cloud_client_param key)
{
    ccs_status_e status = remove_config_parameter(key);
    return map_store_result(status);
}

#if !defined(FOTA_USE_EXTERNAL_FW_KEY)
int fota_nvm_fw_encryption_key_get(uint8_t buffer[FOTA_ENCRYPT_KEY_SIZE])
{
    size_t bytes_read;
    int ret = fota_nvm_get(FOTA_ENCRYPT_KEY, buffer, FOTA_ENCRYPT_KEY_SIZE, &bytes_read);
    FOTA_DBG_ASSERT(ret || (FOTA_ENCRYPT_KEY_SIZE == bytes_read));
    return ret;
}

int fota_nvm_fw_encryption_key_set(const uint8_t buffer[FOTA_ENCRYPT_KEY_SIZE])
{
    return fota_nvm_set(FOTA_ENCRYPT_KEY, buffer, FOTA_ENCRYPT_KEY_SIZE);
}

int fota_nvm_fw_encryption_key_delete(void)
{
    return fota_nvm_remove(FOTA_ENCRYPT_KEY);
}
#endif  // !defined(FOTA_USE_EXTERNAL_FW_KEY)
/******************************************************************************************************/
/*                        Update x509 Certificate                                                     */
/******************************************************************************************************/
#if defined(FOTA_USE_UPDATE_X509)

#if defined(MBED_CLOUD_DEV_UPDATE_CERT)

extern const uint8_t arm_uc_default_certificate[];
extern const uint16_t arm_uc_default_certificate_size;

#if defined(FOTA_USE_EXTERNAL_CERT)
// in this case we are simulating an externally provided certificate getter function
// based on FOTA developer certificate (auto-generated)

int fota_nvm_get_update_certificate(uint8_t *buffer, size_t size, size_t *bytes_read)
{
    memcpy(buffer, arm_uc_default_certificate, arm_uc_default_certificate_size);
    *bytes_read = arm_uc_default_certificate_size;
    return 0;
}

#else  // !defined(FOTA_USE_EXTERNAL_CERT)
// implement setter functions that will be called from fota_dev_init()

/** We always saving certificate buffer max size, because storage backbends may have a requirement for
*   fixed size values when overwriting - the keys.
*   The assumption here is that the value of the certificate is ASN.1 encoded thus the parser will discard the trailing bytes.
*   Same goes to manifest.
*/

int fota_nvm_update_cert_set(void)
{
    uint8_t *buffer_fota_certificate = malloc(FOTA_CERT_MAX_SIZE);
    if (!buffer_fota_certificate) {
        FOTA_TRACE_ERROR("FOTA buffer_fota_certificate - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    memset(buffer_fota_certificate, 0, FOTA_CERT_MAX_SIZE);
    size_t bytes_read;

    memcpy(buffer_fota_certificate, arm_uc_default_certificate, arm_uc_default_certificate_size);

    int ret = fota_nvm_get_update_certificate(buffer_fota_certificate, FOTA_CERT_MAX_SIZE, &bytes_read);

    if ((ret == FOTA_STATUS_NOT_FOUND) ||
            (ret == FOTA_STATUS_SUCCESS && 0 != memcmp(buffer_fota_certificate, arm_uc_default_certificate, arm_uc_default_certificate_size))) {
        ret = fota_nvm_set(UPDATE_CERTIFICATE, buffer_fota_certificate, FOTA_CERT_MAX_SIZE);
    }

    free(buffer_fota_certificate);
    return ret;
}

#endif  // defined(FOTA_USE_EXTERNAL_CERT)
#endif  // defined(MBED_CLOUD_DEV_UPDATE_CERT)

#if !defined(FOTA_USE_EXTERNAL_CERT)

int fota_nvm_get_update_certificate(uint8_t *buffer, size_t size, size_t *bytes_read)
{
    return fota_nvm_get(UPDATE_CERTIFICATE, buffer, size, bytes_read);
}

#endif  // !defined(FOTA_USE_EXTERNAL_CERT)
#endif  // defined(FOTA_USE_UPDATE_X509)

/******************************************************************************************************/
/*                        Update public key                                                           */
/******************************************************************************************************/
#if defined(FOTA_USE_UPDATE_RAW_PUBLIC_KEY)
#if defined(MBED_CLOUD_DEV_UPDATE_RAW_PUBLIC_KEY)

extern const uint8_t arm_uc_update_public_key[];

#if defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY)
// in this case we are simulating an externally provided update public key
// getter function based on FOTA developer certificate (auto-generated)
int fota_nvm_get_update_public_key(uint8_t buffer[FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE])
{
    memcpy(buffer, arm_uc_update_public_key, FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE);
    return FOTA_STATUS_SUCCESS;
}
#else
// implement setter functions that will be called from fota_dev_init()
int fota_nvm_set_update_public_key(void)
{
    uint8_t *buffer_raw_key = malloc(FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE);
    if (!buffer_raw_key) {
        FOTA_TRACE_ERROR("FOTA buffer_raw_key - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    memcpy(buffer_raw_key, arm_uc_update_public_key, FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE);

    int ret = fota_nvm_get_update_public_key(buffer_raw_key);

    if ((ret == FOTA_STATUS_NOT_FOUND) ||
            (ret == FOTA_STATUS_SUCCESS && 0 != memcmp(buffer_raw_key, arm_uc_update_public_key, FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE))) {
        ret = fota_nvm_set(UPDATE_PUBKEY, buffer_raw_key, FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE);
    }

    free(buffer_raw_key);
    return ret;
}
#endif  // defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY)
#endif  // defined(MBED_CLOUD_DEV_UPDATE_RAW_PUBLIC_KEY)

#if !defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY)
int fota_nvm_get_update_public_key(uint8_t buffer[FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE])
{
    size_t bytes_read;
    int ret = fota_nvm_get(UPDATE_PUBKEY, buffer, FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE, &bytes_read);
    FOTA_DBG_ASSERT(ret || (FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE == bytes_read));
    return ret;
}
#endif  // !defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY)


#endif  // defined(FOTA_USE_UPDATE_RAW_PUBLIC_KEY)§

/******************************************************************************************************/
/*                        VENDOR and CLASS IDs                                                        */
/******************************************************************************************************/
#if defined(MBED_CLOUD_DEV_UPDATE_ID)

extern const uint8_t arm_uc_class_id[];
extern const uint8_t arm_uc_vendor_id[];

#if defined(FOTA_USE_EXTERNAL_IDS)
// in this case we are simulating an externally provided class & vendor IDs
// based on FOTA developer IDs (auto-generated)

int fota_nvm_get_class_id(uint8_t buffer[FOTA_GUID_SIZE])
{
    memcpy(buffer, arm_uc_class_id, FOTA_GUID_SIZE);
    return 0;
}

int fota_nvm_get_vendor_id(uint8_t buffer[FOTA_GUID_SIZE])
{
    memcpy(buffer, arm_uc_vendor_id, FOTA_GUID_SIZE);
    return 0;
}
#else  // !defined(FOTA_USE_EXTERNAL_IDS)
// implement setter functions that will be called from fota_dev_init()

int fota_nvm_update_class_id_set(void)
{
    uint8_t buffer[FOTA_GUID_SIZE] = {0};

    int ret = fota_nvm_get_class_id(buffer);

    if (ret == FOTA_STATUS_NOT_FOUND ||
            (ret == FOTA_STATUS_SUCCESS &&
             0 != memcmp(buffer, arm_uc_class_id, FOTA_GUID_SIZE))) {
        ret = fota_nvm_set(UPDATE_CLASS_ID, arm_uc_class_id, FOTA_GUID_SIZE);
    }

    return ret;
}

int fota_nvm_update_vendor_id_set(void)
{
    uint8_t buffer[FOTA_GUID_SIZE] = {0};

    int ret = fota_nvm_get_vendor_id(buffer);

    if (ret == FOTA_STATUS_NOT_FOUND ||
            (ret == FOTA_STATUS_SUCCESS &&
             0 != memcmp(buffer, arm_uc_vendor_id, FOTA_GUID_SIZE))) {
        ret = fota_nvm_set(UPDATE_VENDOR_ID, arm_uc_vendor_id, FOTA_GUID_SIZE);
    }

    return ret;
}
#endif  // defined(FOTA_USE_EXTERNAL_IDS)

#endif  // defined(MBED_CLOUD_DEV_UPDATE_ID)

#if !defined(FOTA_USE_EXTERNAL_IDS)
// NVM implementaton for class and vendor IDs getter functions

int fota_nvm_get_class_id(uint8_t buffer[FOTA_GUID_SIZE])
{
    size_t bytes_read;
    int ret = fota_nvm_get(UPDATE_CLASS_ID, buffer, FOTA_GUID_SIZE, &bytes_read);
    FOTA_DBG_ASSERT(ret || (FOTA_GUID_SIZE == bytes_read));
    return ret;

}

int fota_nvm_get_vendor_id(uint8_t buffer[FOTA_GUID_SIZE])
{
    size_t bytes_read;
    int ret = fota_nvm_get(UPDATE_VENDOR_ID, buffer, FOTA_GUID_SIZE, &bytes_read);
    FOTA_DBG_ASSERT(ret || (FOTA_GUID_SIZE == bytes_read));
    return ret;

}

#endif  // !defined(FOTA_USE_EXTERNAL_IDS)

/** We always saving manifest buffer max size, because storage backbends may have a requirement for
*   fixed size values when overwriting - the keys.
*   The assumption here is that the value of the manifest is ASN.1 encoded thus the parser will discard the trailing bytes.
*   Same goes to certificate.
*/

int fota_nvm_manifest_set(const uint8_t *buffer, size_t buffer_size)
{
    int ret = FOTA_STATUS_INTERNAL_ERROR;

    if (FOTA_MANIFEST_MAX_SIZE < buffer_size) {
        FOTA_TRACE_ERROR("Manifest size is too big for persisting %zu", buffer_size);
        return FOTA_STATUS_INSUFFICIENT_STORAGE;
    }

    uint8_t *manifest = malloc(FOTA_MANIFEST_MAX_SIZE);

    if (!manifest) {
        FOTA_TRACE_ERROR("FOTA manifest - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    memset(manifest, 0, FOTA_MANIFEST_MAX_SIZE);
    memcpy(manifest, buffer, buffer_size);

    ret = fota_nvm_set(FOTA_MANIFEST_KEY, manifest, FOTA_MANIFEST_MAX_SIZE);
    free(manifest);

    return ret;
}

int fota_nvm_manifest_get(uint8_t *buffer, size_t buffer_size, size_t *bytes_read)
{
    return fota_nvm_get(FOTA_MANIFEST_KEY, buffer, buffer_size, bytes_read);
}

int fota_nvm_manifest_delete(void)
{
    fota_nvm_remove(FOTA_MANIFEST_KEY);
    return FOTA_STATUS_SUCCESS;
}

#define COMP_VER_BASE_KEY_SIZE 6

// These two APIs can only be supported with a key list of string keys. Default integer keys cannot work.
int fota_nvm_comp_version_set(const char *comp_name, fota_component_version_t version)
{
    FOTA_DBG_ASSERT(strlen(FOTA_COMP_VER_BASE) <= COMP_VER_BASE_KEY_SIZE);
    char key[COMP_VER_BASE_KEY_SIZE + FOTA_COMPONENT_MAX_NAME_SIZE];
    sprintf(key, "%s%s", FOTA_COMP_VER_BASE, comp_name);
    return fota_nvm_set(key, (uint8_t *)&version, sizeof(version));
}

int fota_nvm_comp_version_get(const char *comp_name, fota_component_version_t *version)
{
    FOTA_DBG_ASSERT(strlen(FOTA_COMP_VER_BASE) <= COMP_VER_BASE_KEY_SIZE);
    char key[COMP_VER_BASE_KEY_SIZE + FOTA_COMPONENT_MAX_NAME_SIZE];
    size_t bytes_read;
    sprintf(key, "%s%s", FOTA_COMP_VER_BASE, comp_name);
    return fota_nvm_get(key, (uint8_t *)version, sizeof(*version), &bytes_read);
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
