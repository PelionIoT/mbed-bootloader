// ----------------------------------------------------------------------------
// Copyright 2021 Pelion Ltd.
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

#include "fota/fota_config.h"
#include "fota/fota_status.h"
#include "fota/fota_block_device.h"

#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_EXTERNAL_BD)
//Should be compiled only for nxp freertos and nxp bootloader 
#if defined(__NXP_FREERTOS__) || defined(FLASH_W25Q) ||  defined(FLASH_MT25Q) || defined(FLASH_MX25R)
#include "ExternalBlockDevice.h"

// This ifdef is here (always true) to prevent astyle from indenting enclosed functions
#ifdef __cplusplus
extern "C" {
#endif


/*Fota block device implementation for external bd of NXP LPC */
using namespace mbed;
static bool initialized = false;
static ExternalBlockDevice *bd = 0;

int fota_bd_init(void)
{
    if (initialized) {
        return 0;
    }
    if (!bd) {
        bd = new ExternalBlockDevice();
    }

    if (!bd) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    int ret = bd->init();
    if (!ret) {
        initialized = true;
    }
    return ret;
}

int fota_bd_deinit(void)
{

    if (!initialized) {
        return 0;
    }

    int ret = bd->deinit();

    delete bd;
    initialized = false;

    return ret;
}

int fota_bd_size(size_t *size)
{
    FOTA_ASSERT(bd);

    *size = (size_t)bd->size();

    return 0;
}

int fota_bd_read(void *buffer, size_t addr, size_t size)
{
    FOTA_ASSERT(bd);
    return bd->read(buffer,(bd_addr_t)addr, (bd_size_t)size);
}

int fota_bd_program(const void *buffer, size_t addr, size_t size)
{
    FOTA_ASSERT(bd);
    return bd->program(buffer, addr, size);
}

int fota_bd_erase(size_t addr, size_t size)
{
    FOTA_ASSERT(bd);
    return bd->erase((bd_addr_t)addr, (bd_size_t)size);
}

int fota_bd_get_read_size(size_t *read_size)
{
    FOTA_ASSERT(bd);
    *read_size = (size_t)bd->get_read_size();
    return 0;
}

int fota_bd_get_program_size(size_t *prog_size)
{
    FOTA_ASSERT(bd);
    *prog_size = (size_t)bd->get_program_size();
    return 0;
}

int fota_bd_get_erase_size(size_t addr, size_t *erase_size)
{
    FOTA_ASSERT(bd);
    *erase_size = (size_t)bd->get_erase_size();
    return 0;
}

int fota_bd_get_erase_value(int *erase_value)
{
    FOTA_DBG_ASSERT(initialized);
    *erase_value = (int)bd->get_erase_value();
    return 0;
}
size_t fota_bd_physical_addr_to_logical_addr(size_t phys_addr)
{
    return phys_addr;
}

#ifdef __cplusplus
}
#endif
#endif  // __NXP_FREERTOS__
#endif  // MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_EXTERNAL_BD)
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
