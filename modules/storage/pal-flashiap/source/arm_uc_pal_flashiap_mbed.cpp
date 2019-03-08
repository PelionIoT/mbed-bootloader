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

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_FLASHIAP) && (ARM_UC_FEATURE_PAL_FLASHIAP == 1)
#if defined(TARGET_LIKE_MBED)

#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"
#include "mbed.h"

SingletonPtr<FlashIAP> flash;

int32_t arm_uc_flashiap_init(void)
{
    /* Workaround for https://github.com/ARMmbed/mbed-os/issues/4967
     * pal_init calls flash.init() before here. Second call to flash.init() will
     * return -1 error state. Hence we ignore the result of flash.init here.
     */
    flash->init();
    return 0;
}

int32_t arm_uc_flashiap_erase(uint32_t address, uint32_t size)
{
    return flash->erase(address, size);
}

int32_t arm_uc_flashiap_program(const uint8_t *buffer, uint32_t address, uint32_t size)
{
    uint32_t page_size = flash->get_page_size();
    int status = ARM_UC_FLASHIAP_FAIL;

    for (uint32_t i = 0; i < size; i += page_size) {
        status = flash->program(buffer + i, address + i, page_size);
        if (status != ARM_UC_FLASHIAP_SUCCESS) {
            break;
        }
    }

    return status;
}

int32_t arm_uc_flashiap_read(uint8_t *buffer, uint32_t address, uint32_t size)
{
    return flash->read(buffer, address, size);
}

uint32_t arm_uc_flashiap_get_page_size(void)
{
    return flash->get_page_size();
}

uint32_t arm_uc_flashiap_get_sector_size(uint32_t address)
{
    uint32_t sector_size = flash->get_sector_size(address);
    if (sector_size == ARM_UC_FLASH_INVALID_SIZE || sector_size == 0) {
        return ARM_UC_FLASH_INVALID_SIZE;
    } else {
        return sector_size;
    }
}

uint32_t arm_uc_flashiap_get_flash_size(void)
{
    return flash->get_flash_size();
}

uint32_t arm_uc_flashiap_get_flash_start(void)
{
    return flash->get_flash_start();
}

#endif /* TARGET_LIKE_MBED */
#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
