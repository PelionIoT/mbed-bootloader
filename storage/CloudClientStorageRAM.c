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
#ifndef RAM
#define RAM 1113
#endif

// default to RAM if not set and in developer mode
#if !defined(MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE) && MBED_CONF_APP_DEVELOPER_MODE == 1
#define MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE RAM
#endif

#if MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == RAM
#if !defined(MBED_CONF_APP_DEVELOPER_MODE) || MBED_CONF_APP_DEVELOPER_MODE == 0
error "RAM storage can only be used in developer mode"
#endif //!defined(MBED_CONF_APP_DEVELOPER_MODE)

// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "CloudClientStorage.h"
#include "mbed-trace/mbed_trace.h"
#include "ns_list.h"

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#define TRACE_GROUP "mClt"

// Memory key item descriptor
typedef struct ccsMemKeyDesc_ {

    char*                   key_name;      // key name
    uint8_t*                key_data;      // key data
    size_t                  key_data_size; // key data size
    ns_list_link_t          link;          // link in g_mem_kd_list list

} ccsMemKeyDesc_s;

// Memory file descriptors list
static NS_LIST_HEAD(ccsMemKeyDesc_s, link) g_mem_kd_list = NS_LIST_INIT(g_mem_kd_list);

ccs_status_e uninitialize_storage(void)
{
    ccs_status_e status = CCS_STATUS_SUCCESS;
    ccs_status_e rm_status = CCS_STATUS_SUCCESS;

    ns_list_foreach_safe(ccsMemKeyDesc_s, tmp_kd_ctx, &g_mem_kd_list) {
        rm_status = remove_config_parameter(tmp_kd_ctx->key_name);
        if (status == CCS_STATUS_SUCCESS && rm_status != CCS_STATUS_SUCCESS) {
            status = rm_status;
        }
    }

    tr_debug("CloudClientStorage::uninitialize_storage");
    return status;
}

ccs_status_e initialize_storage(void)
{
    ccs_status_e status;
    tr_debug("CloudClientStorage::initialize_storage in RAM mode");
    tr_warn("Warning, you are using storage simulation over RAM.\n");
    status = CCS_STATUS_SUCCESS;
    initialize_developer_mode();
    return status;
}

ccs_status_e get_config_parameter(cloud_client_param key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    ccs_status_e status = CCS_STATUS_SUCCESS;
    ccsMemKeyDesc_s* kd_ctx = NULL;

    tr_debug("CloudClientStorage::get_config_parameter(), key: %s", key);

    /* Check if key exists */
    ns_list_foreach(ccsMemKeyDesc_s, tmp_kd_ctx, &g_mem_kd_list) {
        if (strcmp(key, tmp_kd_ctx->key_name) == 0) {
            kd_ctx = tmp_kd_ctx;
            break;
        }
    }

    if (kd_ctx == NULL) {
        status = CCS_STATUS_KEY_DOESNT_EXIST;
    } else {
        if (buffer_size < kd_ctx->key_data_size) {
            tr_error("get_config_parameter() buffer too small");
            status = CCS_STATUS_MEMORY_ERROR;
        } else {
            *value_length = kd_ctx->key_data_size;
            memcpy(buffer, kd_ctx->key_data, kd_ctx->key_data_size);
            status = CCS_STATUS_SUCCESS;
        }
    }
    tr_debug("CloudClientStorage::get_config_parameter(), ret: %d", status);
    return status;
}

ccs_status_e set_config_parameter(cloud_client_param key, const uint8_t *buffer, const size_t buffer_size)
{
    ccs_status_e status = CCS_STATUS_SUCCESS;
    ccsMemKeyDesc_s* kd_ctx = NULL;

    tr_debug("CloudClientStorage::set_config_parameter(), key: %s", key);

    /* Check if key exists */
    ns_list_foreach(ccsMemKeyDesc_s, tmp_kd_ctx, &g_mem_kd_list) {
        if (strcmp(key, tmp_kd_ctx->key_name) == 0) {
            kd_ctx = tmp_kd_ctx;
            break;
        }
    }

    if (kd_ctx == NULL) {
        /* Allcate new KD */
        kd_ctx = (ccsMemKeyDesc_s*)malloc(sizeof(ccsMemKeyDesc_s));
        if (kd_ctx == NULL) {
            status = CCS_STATUS_MEMORY_ERROR;
            goto done;
        }

        memset(kd_ctx, 0, sizeof(ccsMemKeyDesc_s));

        /* Copy key to kd_ctx->key_name */
        kd_ctx->key_name = (char*)malloc(strlen(key) + 1);
        if (kd_ctx->key_name == NULL) {
            status = CCS_STATUS_MEMORY_ERROR;
            goto done;
        }
        strcpy(kd_ctx->key_name, key);

        /* Copy buffer to kd_ctx->key_data */
        kd_ctx->key_data = (uint8_t*)malloc(buffer_size);
        if (kd_ctx->key_data == NULL) {
            status = CCS_STATUS_MEMORY_ERROR;
            goto done;
        }
        memcpy(kd_ctx->key_data, buffer, buffer_size);
        kd_ctx->key_data_size = buffer_size;

        /* Add KD to list */
        ns_list_add_to_end(&g_mem_kd_list, kd_ctx);

        status = CCS_STATUS_SUCCESS;
done:
        if (status != CCS_STATUS_SUCCESS) {
            if (kd_ctx != NULL) {
                free(kd_ctx->key_name);
                free(kd_ctx->key_data);
                free(kd_ctx);
            }
        }
    } else {
        tr_error("set_config_parameter() key already exist");
        status = CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::set_config_parameter(), ret: %d", status);
    return status;
}

ccs_status_e remove_config_parameter(cloud_client_param key)
{
    ccs_status_e status = CCS_STATUS_SUCCESS;
    ccsMemKeyDesc_s* kd_ctx = NULL;

    tr_debug("CloudClientStorage::remove_config_parameter(), key: %s", key);

    /* Check if key exists */
    ns_list_foreach(ccsMemKeyDesc_s, tmp_kd_ctx, &g_mem_kd_list) {
        if (strcmp(key, tmp_kd_ctx->key_name) == 0) {
            kd_ctx = tmp_kd_ctx;
            break;
        }
    }

    if (kd_ctx == NULL) {
        tr_error("remove_config_parameter() key not exist");
        status = CCS_STATUS_KEY_DOESNT_EXIST;
    } else {
        /* Remove KD from list */
        ns_list_remove(&g_mem_kd_list, kd_ctx);
        free(kd_ctx->key_name);
        free(kd_ctx->key_data);
        free(kd_ctx);
    }

    tr_debug("CloudClientStorage::remove_config_parameter(), ret: %d", status);
    return status;
}

ccs_status_e size_config_parameter(cloud_client_param key, size_t *size_out)
{
    ccs_status_e status = CCS_STATUS_SUCCESS;
    ccsMemKeyDesc_s* kd_ctx = NULL;

    tr_debug("CloudClientStorage::size_config_parameter(), key: %s", key);

    /* Check if key exists */
    ns_list_foreach(ccsMemKeyDesc_s, tmp_kd_ctx, &g_mem_kd_list) {
        if (strcmp(key, tmp_kd_ctx->key_name) == 0) {
            kd_ctx = tmp_kd_ctx;
            break;
        }
    }

    if (kd_ctx == NULL) {
        status = CCS_STATUS_KEY_DOESNT_EXIST;
    } else {
        *size_out = kd_ctx->key_data_size;
        status = CCS_STATUS_SUCCESS;
    }

    tr_debug("CloudClientStorage::size_config_parameter(), ret: %d", status);
    return status;
}

#endif // MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == RAM
