// ----------------------------------------------------------------------------
// Copyright 2021 Pelion.
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

#include "fota/fota_block_device.h"
#include "fota/fota_status.h"

// External BD should supply all these APIs

#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE != FOTA_EXTERNAL_BD)

static bool initialized = false;

#include "BlockDevice.h"

#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_MBED_OS_BD)
#if COMPONENT_FLASHIAP
#include "FlashIAPBlockDevice.h"
#else
#error FlashIAP component should be defined in case of an internal flash block device configuration
#endif
#endif // (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_MBED_OS_BD)

#include <string.h>

static mbed::BlockDevice *bd = 0;

#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_CUSTOM_MBED_OS_BD)
// Should be supplied by application
mbed::BlockDevice *fota_bd_get_custom_bd();
#else //FOTA_INTERNAL_FLASH_MBED_OS_BD or FOTA_DEFAULT_MBED_OS_BD
mbed::BlockDevice *fota_bd_get_custom_bd()
{
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_MBED_OS_BD)
    if (!bd) {
        bd = new FlashIAPBlockDevice(MBED_ROM_START, MBED_ROM_SIZE);
    }
    return bd;

#elif (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_DEFAULT_MBED_OS_BD)
    return mbed::BlockDevice::get_default_instance();
#endif
}
#endif

// This ifdef is here (always true) to prevent astyle from indenting enclosed functions
#ifdef __cplusplus
extern "C" {
#endif

int fota_bd_size(size_t *size)
{
    FOTA_ASSERT(bd);

    *size = (size_t) bd->size();
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_init(void)
{
    if (initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    if (!bd) {
        bd = fota_bd_get_custom_bd();
    }
    FOTA_ASSERT(bd);

    int ret = bd->init();
    if (!ret) {
        initialized = true;
        return FOTA_STATUS_SUCCESS;
    }
    FOTA_TRACE_ERROR("Failed to initialize BlockDevice. error %d", ret);
    return FOTA_STATUS_STORAGE_WRITE_FAILED;
}

int fota_bd_deinit(void)
{
    if (!initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    int ret = bd->deinit();
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_MBED_OS_BD)
    delete bd;
#endif
    bd = 0;
    initialized = false;
    if (!ret) {
        return FOTA_STATUS_SUCCESS;
    }
    FOTA_TRACE_ERROR("Failed to deinitialize BlockDevice. error %d", ret);
    return FOTA_STATUS_INTERNAL_ERROR;
}

int fota_bd_read(void *buffer, size_t addr, size_t size)
{
    int ret;
    FOTA_ASSERT(bd);

    ret = bd->read(buffer, addr, size);
    if (ret) {
        return FOTA_STATUS_STORAGE_READ_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_program(const void *buffer, size_t addr, size_t size)
{
    int ret;
    FOTA_ASSERT(bd);

    ret = bd->program(buffer, addr, size);
    if (ret) {
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_erase(size_t addr, size_t size)
{
    int ret;
    FOTA_ASSERT(bd);

    ret = bd->erase(addr, size);
    if (ret) {
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_read_size(size_t *read_size)
{
    FOTA_ASSERT(bd);

    *read_size = (size_t) bd->get_read_size();
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_program_size(size_t *prog_size)
{
    FOTA_ASSERT(bd);

    *prog_size = (size_t)bd->get_program_size();
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_erase_size(size_t addr, size_t *erase_size)
{
    FOTA_ASSERT(bd);

    *erase_size = (size_t) bd->get_erase_size(addr);
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_erase_value(int *erase_value)
{
    FOTA_ASSERT(bd);

    *erase_value = bd->get_erase_value();
    return FOTA_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif // (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE != FOTA_EXTERNAL_BD)

static bool is_internal_flash_bd()
{
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_MBED_OS_BD)
    return true;
#elif (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_CUSTOM_MBED_OS_BD)
    FOTA_ASSERT(bd);
    const char *bd_type = bd->get_type();
    if (strcmp("FLASHIAP", bd_type) == 0) {
        return true;
    }
    return false;
#else
    return false;
#endif
}

extern "C" size_t fota_bd_physical_addr_to_logical_addr(size_t phys_addr)
{
#ifdef __MBED__
    if (is_internal_flash_bd()) {
        return phys_addr - MBED_ROM_START;
    }
#endif
    return phys_addr;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
