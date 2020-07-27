// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#ifndef CLOUD_CLIENT_STORAGE_H
#define CLOUD_CLIENT_STORAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE
// MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE defines the `cloud_client_param` type and the keys needed by cloud client.
// It may also define additional application specific keys.
#include MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE
#else // not defined MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE

// The supported storage keys

//TODO: this should be removed once mbed_cloud_client_get_rot_128bit() removed from CloudClientStorageCommon.cpp
#define ROOT_OF_TRUST                           "ROOT_OF_TRUST" // "ROT"           /* not used, should be removed */

#define INTERNAL_ENDPOINT                       "INTERNAL_ENDPOINT" // "IEP"
#define ENDPOINT_NAME                           "pelion_wCfgParam_mbed.EndpointName" // "EP"            /* needed by factory client - value can't be modified */
#define BOOTSTRAP_SERVER_PSK_IDENTITY           "BOOTSTRAP_SERVER_PSK_IDENTITY" // "BsPskId"
#define BOOTSTRAP_SERVER_PSK_SECRET             "BOOTSTRAP_SERVER_PSK_SECRET" // "BsPskSc"
#define BOOTSTRAP_SERVER_URI                    "pelion_wCfgParam_mbed.BootstrapServerURI" // "BsUri"
#define BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE    "pelion_wCrtae_mbed.BootstrapServerCACert" // "BsCACert"
#define BOOTSTRAP_DEVICE_CERTIFICATE            "pelion_wCrtae_mbed.BootstrapDeviceCert" // "BsDevCert"
#define BOOTSTRAP_DEVICE_PRIVATE_KEY            "pelion_wPrvKey_mbed.BootstrapDevicePrivateKey" // "BsDevKey"
#define LWM2M_SERVER_PSK_IDENTITY               "LWM2M_SERVER_PSK_IDENTITY" // "LwM2MPskId"
#define LWM2M_SERVER_PSK_SECRET                 "LWM2M_SERVER_PSK_SECRET" // "LwM2MPskSc"
#define LWM2M_SERVER_URI                        "pelion_wCfgParam_mbed.LwM2MServerURI" // "LwM2MUri"      /* needed by factory client - value can't be modified */
#define LWM2M_SERVER_ROOT_CA_CERTIFICATE        "pelion_wCrtae_mbed.LwM2MServerCACert" // "LwM2MCACert"   /* needed by factory client - value can't be modified */
#define LWM2M_DEVICE_CERTIFICATE                "pelion_wCrtae_mbed.LwM2MDeviceCert" // "DevCert"       /* needed by factory client - value can't be modified */
#define LWM2M_DEVICE_PRIVATE_KEY                "pelion_wPrvKey_mbed.LwM2MDevicePrivateKey" // "DevKey"        /* needed by factory client - value can't be modified */
#define UPDATE_PSK_IDENTITY                     "UPDATE_PSK_IDENTITY"
#define UPDATE_PSK_SECRET                       "UPDATE_PSK_SECRET"
#define KEY_VENDOR_ID                           "KEY_VENDOR_ID"
#define KEY_CLASS_ID                            "KEY_CLASS_ID"

#define UPDATE_VENDOR_ID                        "pelion_wCfgParam_mbed.VendorId" // "FWVendorId"
#define UPDATE_CLASS_ID                         "pelion_wCfgParam_mbed.ClassId" // "FWClassId"
#define UPDATE_FINGERPRINT                      "UPDATE_FINGERPRINT" // "FWFngrprnt"
#define UPDATE_CERTIFICATE                      "pelion_wCrtae_mbed.UpdateAuthCert" // "FWUpdateCert"
#define UPDATE_PUBKEY                           "pelion_wCrtae_mbed.UpdatePubKey"

#define SSL_SESSION_DATA                        "SSL_SESSION_DATA" // "SslSessionDt"

#define FOTA_ENCRYPT_KEY                        "FOTA_ENCRYPT_KEY" // "FTEncryptKey"
#define FOTA_SALT_KEY                           "FOTA_SALT_KEY" // ""FTSaltKey"
#define FOTA_MANIFEST_KEY                       "FOTA_MANIFEST_KEY" // ""FTManKey"
#define FOTA_COMP_VER_BASE                      "FTCmpV"

// The data type used by cloud client for the key
typedef const char * cloud_client_param;

#endif // MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE

typedef enum {
    CCS_STATUS_SUCCESS = 0,
    CCS_STATUS_MEMORY_ERROR = 1,
    CCS_STATUS_VALIDATION_FAIL = 2,
    CCS_STATUS_KEY_DOESNT_EXIST = 3,
    CCS_STATUS_ERROR = 4
} ccs_status_e;

/**
*  \brief Uninitializes the underlying storage handle.
*  \return CCS_STATUS_SUCCESS if success, else error number (mapped from SOTP)
*/
ccs_status_e uninitialize_storage(void);

/**
*  \brief Initializes the underlying storage handle.
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e initialize_storage(void);

/**
*  \brief Gets the stored value for the given key.
*  \param key, Key of stored item.
*  \param [in] buffer_size, Length of input buffer in bytes.
*  \param [in] buffer, Buffer to store data on (must be aligned to a 32 bit boundary).
*  \param [out] value_length, Actual length of returned data
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e get_config_parameter(cloud_client_param key, uint8_t *buffer, const size_t buffer_size, size_t *value_length);

/**
*  \brief Gets pointer to the stored value for the given key. Note: this is not available
*  on all implementations and the user may not modify or free the returned buffer.
*  \param key, Key of stored item.
*  \param [in] buffer_size, Length of input buffer in bytes.
*  \param [in] buffer, Buffer to store data on (must be aligned to a 32 bit boundary).
*  \param [out] value_length, Actual length of returned data
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e get_config_parameter_no_copy(cloud_client_param key, const uint8_t **buffer, size_t *value_length);

/**
*  \brief Programs one item of data on storage, given type.
*  \param key, Key of stored item.
*  \param [in] buffer, Buffer containing data  (must be aligned to a 32 bit boundary).
*  \param [in] buffer_size, Item length in bytes.
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e set_config_parameter(cloud_client_param  key, const uint8_t *buffer, const size_t buffer_size);

/**
 * @brief Remove one of item by given key.
 *
 *  \param key, Key of stored item.
 *  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
 */
ccs_status_e remove_config_parameter(cloud_client_param  key);

/**
*  \brief Returns size of data stored on storage, given type.
*  \param key, Key of stored item.
*  \param [in] size_out, Length of input buffer in bytes.
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e size_config_parameter(cloud_client_param  key, size_t *size_out);

/**
 * \brief Function to get the device root of trust
 * \details The device root of trust should be a 128 bit value. It should never leave the device.
 *          It should be unique to the device. It should have enough entropy to avoid conentional
 *          entropy attacks. The porter should implement the following device signature to provide
 *          device root of trust on different platforms.
 *
 * \param key_buf buffer to be filled with the device root of trust.
 * \param length  length of the buffer provided to make sure no overflow occurs.
 *  \return 0 on success, non-zero on failure.
 */
int8_t mbed_cloud_client_get_rot_128bit(uint8_t *key_buf, uint32_t length);

/**
 * \brief Initializes storage from developer certificate
 * \details Private function that checks if storage contains bootstrap credentials and initializes
 *          them from the developer certificate if necessary. Called automatically if needed.
 */
ccs_status_e initialize_developer_mode(void);

#ifdef RESET_STORAGE
/**
 * \brief Remove all keys and related data from a storage.
 * \param partition Partition to be cleared.
 */
ccs_status_e reset_storage(const char *partition);
#endif // RESET_STORAGE

#ifdef __cplusplus
}
#endif
#endif // CLOUD_CLIENT_STORAGE_H
