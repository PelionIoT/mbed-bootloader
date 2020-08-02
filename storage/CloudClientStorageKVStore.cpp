// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#ifndef KVSTORE
#define KVSTORE 1111
#endif

#if MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == KVSTORE

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
#ifdef TARGET_LIKE_MBED
#include "mbed.h"
#else
#include "BlockDevice.h"
using namespace mbed;
#endif
#include "kvstore_global_api.h"
#include <assert.h>

#define STR(x) #x
#define XSTR(x) STR(x)

#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_RESET_DEV_CREDENTIALS
#define KVSTORE_LOCATION_PATH XSTR(MBED_CONF_STORAGE_DEFAULT_KV)
#endif



#define KVSTORE_PATH "/" XSTR(MBED_CONF_STORAGE_DEFAULT_KV) "/"

// max supported key name len
#define MAX_KEY_NAME_LEN 100


#define TRACE_GROUP "mClt"

static ccs_status_e map_kvstore_result(int result);

ccs_status_e uninitialize_storage(void)
{
    ccs_status_e status;
    tr_debug("CloudClientStorage::uninitialize_storage");
    status = CCS_STATUS_SUCCESS;
    return status;
}

ccs_status_e initialize_storage(void)
{
    ccs_status_e status;
    tr_debug("CloudClientStorage::initialize_storage in KVStore mode");
    status = CCS_STATUS_SUCCESS;
#if MBED_CONF_APP_DEVELOPER_MODE == 1
// TODO: remove this from library.
#warning "Do not expect MCC to initialize certificates. Will be removed."
#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_RESET_DEV_CREDENTIALS
    tr_info("CloudClientStorage::initialize_storage resetting KVStore");
    status = map_kvstore_result(kv_reset(KVSTORE_LOCATION_PATH));
    if (status != CCS_STATUS_SUCCESS) {
        tr_error("initialize_storage() failed: couldn't reset KVStore");
        return status;
    }
#endif
    initialize_developer_mode();
#endif
    return status;
}

ccs_status_e get_config_parameter(cloud_client_param key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    ccs_status_e status;
    char key_name[sizeof(KVSTORE_PATH) + MAX_KEY_NAME_LEN] = { KVSTORE_PATH };
    if (strlen(key) > MAX_KEY_NAME_LEN) {
        tr_error("CloudClientStorage::get_config_parameter(), key name %s longer then %d", key, MAX_KEY_NAME_LEN);
        return CCS_STATUS_ERROR;
    }
    memcpy(key_name + strlen(KVSTORE_PATH), key, strlen(key));
    tr_debug("CloudClientStorage::get_config_parameter(), key name %s", key_name);
    int result = kv_get(key_name, (void *)buffer, buffer_size, value_length);
    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::get_config_parameter(), ret: %d, size: %lu", status, (unsigned long)*value_length);

    return status;
}

ccs_status_e set_config_parameter(cloud_client_param key, const uint8_t *buffer, const size_t buffer_size)
{
    ccs_status_e status;
    char key_name[sizeof(KVSTORE_PATH) + MAX_KEY_NAME_LEN] = { KVSTORE_PATH };
    if (strlen(key) > MAX_KEY_NAME_LEN) {
        tr_error("CloudClientStorage::set_config_parameter(), key name %s longer then %d", key, MAX_KEY_NAME_LEN);
        return CCS_STATUS_ERROR;
    }
    memcpy(key_name + strlen(KVSTORE_PATH), key, strlen(key));
    tr_debug("CloudClientStorage::set_config_parameter(), key name %s", key_name);

    int result = kv_set(key_name, (void *)buffer, buffer_size, 0);

    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::set_config_parameter(), ret: %d, size %lu", status, (unsigned long)buffer_size);

    return status;
}

ccs_status_e remove_config_parameter(cloud_client_param key)
{
    ccs_status_e status;
    char key_name[sizeof(KVSTORE_PATH) + MAX_KEY_NAME_LEN] = { KVSTORE_PATH };
    if (strlen(key) > MAX_KEY_NAME_LEN) {
        tr_error("CloudClientStorage::remove_config_parameter(), key name %s longer then %d", key, MAX_KEY_NAME_LEN);
        return CCS_STATUS_ERROR;
    }
    memcpy(key_name + strlen(KVSTORE_PATH), key, strlen(key));
    tr_debug("CloudClientStorage::remove_config_parameter(), key name %s", key_name);

    int result = kv_remove(key_name);

    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::remove_config_parameter(), ret: %d", status);

    return status;
}

ccs_status_e size_config_parameter(cloud_client_param key, size_t *size_out)
{
    ccs_status_e status;
    char key_name[sizeof(KVSTORE_PATH) + MAX_KEY_NAME_LEN] = { KVSTORE_PATH };
    if (strlen(key) > MAX_KEY_NAME_LEN) {
        tr_error("CloudClientStorage::size_config_parameter(), key name %s longer then %d", key, MAX_KEY_NAME_LEN);
        return CCS_STATUS_ERROR;
    }
    memcpy(key_name + strlen(KVSTORE_PATH), key, strlen(key));
    tr_debug("CloudClientStorage::size_config_parameter(), key name %s", key_name);
    kv_info_t info;
    int result = kv_get_info(key_name, &info);
    *size_out = info.size;
    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::size_config_parameter(), ret: %d", status);

    return status;
}

static ccs_status_e map_kvstore_result(int result)
{
    ccs_status_e status = CCS_STATUS_ERROR;
    tr_debug("kvstore_result %d", (int)result);
    switch (result) {
        case MBED_SUCCESS:
            status = CCS_STATUS_SUCCESS;
            break;
        case MBED_ERROR_ITEM_NOT_FOUND:
            status = CCS_STATUS_KEY_DOESNT_EXIST;
            break;
        case MBED_ERROR_INVALID_DATA_DETECTED:
        case MBED_ERROR_INVALID_ARGUMENT:
        case MBED_ERROR_INVALID_SIZE:
        case MBED_ERROR_AUTHENTICATION_FAILED:
        case MBED_ERROR_RBP_AUTHENTICATION_FAILED:
            status = CCS_STATUS_VALIDATION_FAIL;
            break;
        case MBED_ERROR_MEDIA_FULL:
            status = CCS_STATUS_MEMORY_ERROR;
            break;
        case MBED_ERROR_READ_FAILED:
        case MBED_ERROR_WRITE_FAILED:
        case MBED_ERROR_FAILED_OPERATION:
            status = CCS_STATUS_ERROR;
            break;
    }
    return status;
}

#ifdef RESET_STORAGE
ccs_status_e reset_storage(const char *kvstore_path)
{
    return map_kvstore_result(kv_reset(kvstore_path));
}
#endif // RESET_STORAGE



#endif // MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == KVSTORE
