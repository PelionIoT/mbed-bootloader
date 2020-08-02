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
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <string.h>
#include "CloudClientStorage.h"
#include "mbed-trace/mbed_trace.h"
#define DEVICE_KEY_SIZE_IN_BYTES (128/8)

#define TRACE_GROUP "mClt"

#if MBED_CONF_APP_DEVELOPER_MODE == 1
#include "protoman.h"

#ifdef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

extern const char MBED_CLOUD_DEV_LWM2M_ENDPOINT_NAME[];
extern const char MBED_CLOUD_DEV_ACCOUNT_ID[];
extern const char MBED_CLOUD_DEV_LWM2M_SERVER_URI[];
extern const uint32_t MBED_CLOUD_DEV_LWM2M_DEVICE_CERTIFICATE_SIZE;
extern const uint8_t MBED_CLOUD_DEV_LWM2M_DEVICE_CERTIFICATE[];
extern const uint32_t MBED_CLOUD_DEV_LWM2M_SERVER_ROOT_CA_CERTIFICATE_SIZE;
extern const uint8_t MBED_CLOUD_DEV_LWM2M_SERVER_ROOT_CA_CERTIFICATE[];
extern const uint32_t MBED_CLOUD_DEV_LWM2M_DEVICE_PRIVATE_KEY_SIZE;
extern const uint8_t MBED_CLOUD_DEV_LWM2M_DEVICE_PRIVATE_KEY[];

#else // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

extern const char MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME[];
extern const char MBED_CLOUD_DEV_ACCOUNT_ID[];
extern const char MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI[];

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_IDENTITY[];
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_SECRET[];
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_IDENTITY_SIZE;
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_SECRET_SIZE;
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE_SIZE;
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE[];
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE_SIZE;
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE[];
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY_SIZE;
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY[];
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

#endif  // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

#if defined (MBED_CLOUD_CLIENT_SUPPORT_UPDATE) && defined (PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
extern const uint8_t arm_uc_vendor_id[];
extern const uint16_t arm_uc_vendor_id_size;
extern const uint8_t arm_uc_class_id[];
extern const uint16_t arm_uc_class_id_size;
extern const uint8_t arm_uc_default_fingerprint[];
extern const uint16_t arm_uc_default_fingerprint_size;
extern const uint8_t arm_uc_default_certificate[];
extern const uint16_t arm_uc_default_certificate_size;
#endif

#if defined (MBED_CLOUD_CLIENT_SUPPORT_UPDATE) && defined (PROTOMAN_SECURITY_ENABLE_PSK)
extern const uint8_t arm_uc_vendor_id[];
extern const uint16_t arm_uc_vendor_id_size;
extern const uint8_t arm_uc_class_id[];
extern const uint16_t arm_uc_class_id_size;
extern const uint8_t arm_uc_default_psk[];
extern const uint8_t arm_uc_default_psk_size;
extern const uint16_t arm_uc_default_psk_bits;
extern const uint8_t arm_uc_default_psk_id[];
extern const uint8_t arm_uc_default_psk_id_size;
#endif

ccs_status_e initialize_developer_mode(void)
{
    size_t size = 0;

#ifdef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    if (CCS_STATUS_SUCCESS != size_config_parameter(ENDPOINT_NAME, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(ENDPOINT_NAME, (const uint8_t*)MBED_CLOUD_DEV_LWM2M_ENDPOINT_NAME, strlen(MBED_CLOUD_DEV_LWM2M_ENDPOINT_NAME))) {
            tr_error("initialize_developer_mode() - couldn't set ENDPOINT_NAME");
            return CCS_STATUS_ERROR;
        }
    }

#else
    if (CCS_STATUS_SUCCESS != size_config_parameter(ENDPOINT_NAME, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(ENDPOINT_NAME, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME, strlen(MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME))) {
            tr_error("initialize_developer_mode() - couldn't set ENDPOINT_NAME");
            return CCS_STATUS_ERROR;
        }
    }
#endif

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)

    tr_info("storing hard coded PSK bootstrap credentials");

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_SERVER_URI, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_SERVER_URI, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI, strlen(MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI))) {
            tr_error("initialize_developer_mode() - couldn't set BOOTSTRAP_SERVER_URI");
            return CCS_STATUS_ERROR;
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_SERVER_PSK_SECRET, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_SERVER_PSK_SECRET, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_SECRET, MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_SECRET_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set BOOTSTRAP_SERVER_PSK_SECRET");
            return CCS_STATUS_ERROR;
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_SERVER_PSK_IDENTITY, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_SERVER_PSK_IDENTITY, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_IDENTITY, MBED_CLOUD_DEV_BOOTSTRAP_PRE_SHARED_KEY_IDENTITY_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set BOOTSTRAP_SERVER_PSK_IDENTITY");
            return CCS_STATUS_ERROR;
        }
    }
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE

        if (CCS_STATUS_SUCCESS != size_config_parameter(KEY_VENDOR_ID, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(KEY_VENDOR_ID, (const uint8_t*)arm_uc_vendor_id, arm_uc_vendor_id_size)) {
                tr_error("initialize_developer_mode() - couldn't set KEY_VENDOR_ID");
            }
        }

        if (CCS_STATUS_SUCCESS != size_config_parameter(KEY_CLASS_ID, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(KEY_CLASS_ID, (const uint8_t*)arm_uc_class_id, arm_uc_class_id_size)) {
                tr_error("initialize_developer_mode() - couldn't set KEY_CLASS_ID");
            }
        }

        if (CCS_STATUS_SUCCESS != size_config_parameter(UPDATE_PSK_IDENTITY, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(UPDATE_PSK_IDENTITY, (const uint8_t*)arm_uc_default_psk_id, arm_uc_default_psk_id_size)) {
                tr_error("initialize_developer_mode() - couldn't set UPDATE_PSK_IDENTITY");
            }
        }

        if (CCS_STATUS_SUCCESS != size_config_parameter(UPDATE_PSK_SECRET, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(UPDATE_PSK_SECRET, (const uint8_t*)arm_uc_default_psk, arm_uc_default_psk_size)) {
                tr_error("initialize_developer_mode() - couldn't set UPDATE_PSK_SECRET");
            }
        }
#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#endif // PROTOMAN_SECURITY_ENABLE_PSK

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

#ifdef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    tr_info("storing hard coded lwm2m credentials");

    if (CCS_STATUS_SUCCESS != size_config_parameter(LWM2M_SERVER_URI, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(LWM2M_SERVER_URI, (const uint8_t*)MBED_CLOUD_DEV_LWM2M_SERVER_URI, strlen(MBED_CLOUD_DEV_LWM2M_SERVER_URI))) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_URI");
            return CCS_STATUS_ERROR;
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(LWM2M_DEVICE_CERTIFICATE, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(LWM2M_DEVICE_CERTIFICATE, (const uint8_t*)MBED_CLOUD_DEV_LWM2M_DEVICE_CERTIFICATE, MBED_CLOUD_DEV_LWM2M_DEVICE_CERTIFICATE_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_DEVICE_CERTIFICATE");
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, (const uint8_t*)MBED_CLOUD_DEV_LWM2M_SERVER_ROOT_CA_CERTIFICATE, MBED_CLOUD_DEV_LWM2M_SERVER_ROOT_CA_CERTIFICATE_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_ROOT_CA_CERTIFICATE");
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(LWM2M_DEVICE_PRIVATE_KEY, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(LWM2M_DEVICE_PRIVATE_KEY, (const uint8_t*)MBED_CLOUD_DEV_LWM2M_DEVICE_PRIVATE_KEY, MBED_CLOUD_DEV_LWM2M_DEVICE_PRIVATE_KEY_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_DEVICE_PRIVATE_KEY");
        }
    }

#else

    tr_info("storing hard coded bootstrap credentials");

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_SERVER_URI, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_SERVER_URI, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI, strlen(MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI))) {
            tr_error("initialize_developer_mode() - couldn't set BOOTSTRAP_SERVER_URI");
            return CCS_STATUS_ERROR;
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_DEVICE_CERTIFICATE, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_DEVICE_CERTIFICATE, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE, MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_DEVICE_CERTIFICATE");
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_ROOT_CA_CERTIFICATE");
        }
    }

    if (CCS_STATUS_SUCCESS != size_config_parameter(BOOTSTRAP_DEVICE_PRIVATE_KEY, &size) || !size) {
        if (CCS_STATUS_SUCCESS != set_config_parameter(BOOTSTRAP_DEVICE_PRIVATE_KEY, (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY, MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY_SIZE)) {
            tr_error("initialize_developer_mode() - couldn't set LWM2M_SERVER_DEVICE_PRIVATE_KEY");
        }
    }
#endif

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE

        if (CCS_STATUS_SUCCESS != size_config_parameter(UPDATE_VENDOR_ID, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(UPDATE_VENDOR_ID, (const uint8_t*)arm_uc_vendor_id, arm_uc_vendor_id_size)) {
                tr_error("initialize_developer_mode() - couldn't set UPDATE_VENDOR_ID");
            }
        }

        if (CCS_STATUS_SUCCESS != size_config_parameter(UPDATE_CLASS_ID, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(UPDATE_CLASS_ID, (const uint8_t*)arm_uc_class_id, arm_uc_class_id_size)) {
                tr_error("initialize_developer_mode() - couldn't set UPDATE_CLASS_ID");
            }
        }

        if (CCS_STATUS_SUCCESS != size_config_parameter(UPDATE_FINGERPRINT, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(UPDATE_FINGERPRINT, (const uint8_t*)arm_uc_default_fingerprint, arm_uc_default_fingerprint_size)) {
                tr_error("initialize_developer_mode() - couldn't set UPDATE_FINGERPRINT");
            }
        }

        if (CCS_STATUS_SUCCESS != size_config_parameter(UPDATE_CERTIFICATE, &size) || !size) {
            if (CCS_STATUS_SUCCESS != set_config_parameter(UPDATE_CERTIFICATE, (const uint8_t*)arm_uc_default_certificate, arm_uc_default_certificate_size)) {
                tr_error("initialize_developer_mode() - couldn't set UPDATE_CERTIFICATE");
            }
        }
#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

    return CCS_STATUS_SUCCESS;
}
#endif // defined(MBED_CONF_APP_DEVELOPER_MODE)

/**
 * @brief Function to get the device root of trust
 * @details The device root of trust should be a 128 bit value. It should never leave the device.
 *          It should be unique to the device. It should have enough entropy to avoid contentional
 *          entropy attacks. The porter should implement the following device signature to provide
 *          device root of trust on different platforms.
 *
 * @param key_buf buffer to be filled with the device root of trust.
 * @param length  length of the buffer provided to make sure no overflow occurs.
 *
 * @return 0 on success, non-zero on failure.
 */

int8_t mbed_cloud_client_get_rot_128bit(uint8_t *key_buf, uint32_t length)
{

    if (length < DEVICE_KEY_SIZE_IN_BYTES || key_buf == NULL)
    {
        return -1;
    }

#if MBED_CONF_APP_DEVELOPER_MODE == 1
#warning "You are using insecure Root Of Trust implementation, DO NOT USE IN PRODUCTION ENVIRONMENTS. REPLACE WITH A PROPER IMPLEMENTATION BEFORE USE"
    for (uint8_t i = 0; i < DEVICE_KEY_SIZE_IN_BYTES; i++)
    {
        key_buf[i] = i;
    }
#else
    // RoT key size is 128 bits
    uint8_t buffer[DEVICE_KEY_SIZE_IN_BYTES];
    size_t real_size = 0;
    if (CCS_STATUS_SUCCESS == get_config_parameter(ROOT_OF_TRUST, buffer, DEVICE_KEY_SIZE_IN_BYTES, &real_size)) {
        tr_info("mbed_cloud_client_get_rot_128bit - read RoT from configuration, size %d", (int)real_size);
    }
    else {
        return -1;
    }
    memcpy(key_buf, buffer, real_size);
    memset(buffer, 0, DEVICE_KEY_SIZE_IN_BYTES);
#endif

    return 0;
}
