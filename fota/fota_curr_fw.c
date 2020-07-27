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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_curr_fw.h"
#include "fota/fota_status.h"
#include <stdio.h>

#if !defined(FOTA_CUSTOM_CURR_FW_STRUCTURE) || (!FOTA_CUSTOM_CURR_FW_STRUCTURE)
#if defined(__MBED__)
// Bootloader and application have different defines
#if !defined(APPLICATION_ADDR)
#if defined(MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS)
#define APPLICATION_ADDR MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS
#elif defined(MBED_CONF_TARGET_APP_OFFSET)
#define APPLICATION_ADDR MBED_CONF_TARGET_APP_OFFSET
#else
#error Application start address not defined
#endif
#endif  // !defined(APPLICATION_ADDR)

#if !defined(HEADER_ADDR)
#if defined(MBED_CONF_MBED_BOOTLOADER_APPLICATION_HEADER_ADDRESS)
#define HEADER_ADDR MBED_CONF_MBED_BOOTLOADER_APPLICATION_HEADER_ADDRESS
#elif defined(MBED_CONF_TARGET_HEADER_OFFSET)
#define HEADER_ADDR MBED_CONF_TARGET_HEADER_OFFSET
#else
#error Header start address not defined
#endif
#endif  // !defined(HEADER_ADDR)


// The following two functions should be overridden in the non mbed-os cases.
uint8_t *fota_curr_fw_get_app_start_addr(void)
{
#ifdef APPLICATION_ADDR
    return (uint8_t *) APPLICATION_ADDR;
#else
//#error No address was defined for application
    FOTA_ASSERT(!"No app start address defined");
    return NULL;
#endif
}

uint8_t *fota_curr_fw_get_app_header_addr(void)
{
#ifdef HEADER_ADDR
    return (uint8_t *) HEADER_ADDR;
#else
//#error No address was defined for application header
    FOTA_ASSERT(!"No app start address defined");
    return NULL;
#endif
}

#endif // defined(__MBED__)

int fota_curr_fw_read(uint8_t *buf, uint32_t offset, uint32_t size, uint32_t *num_read)
{
    fota_header_info_t header_info;
    int ret = FOTA_STATUS_INTERNAL_ERROR;

    ret = fota_curr_fw_read_header(&header_info);
    if (ret) {
        return ret;
    }

    if (offset >= header_info.fw_size) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    *num_read = header_info.fw_size - offset;
    if (*num_read > size) {
        *num_read = size;
    }

    memcpy(buf, fota_curr_fw_get_app_start_addr() + offset, *num_read);
    return FOTA_STATUS_SUCCESS;

}

int fota_curr_fw_get_digest(uint8_t *buf)
{
    fota_header_info_t curr_fw_info;
    int ret = fota_curr_fw_read_header(&curr_fw_info);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to read current header");
        return ret;
    }
    memcpy(buf, curr_fw_info.digest, FOTA_CRYPTO_HASH_SIZE);
    return FOTA_STATUS_SUCCESS;
}

#endif // !defined(FOTA_CUSTOM_CURR_FW_STRUCTURE) || (!FOTA_CUSTOM_CURR_FW_STRUCTURE)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
