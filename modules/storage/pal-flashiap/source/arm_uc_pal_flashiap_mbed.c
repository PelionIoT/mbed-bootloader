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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stddef.h>

#include "update-client-pal-flashiap/arm_uc_pal_flashiap.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"
#include "flash_api.h"

static flash_t arm_uc_flash_obj = { 0 };

int32_t arm_uc_flashiap_init(void)
{
    return flash_init(&arm_uc_flash_obj);
}

int32_t arm_uc_flashiap_free(void)
{
    return flash_free(&arm_uc_flash_obj);
}

int32_t arm_uc_flashiap_erase(uint32_t address, uint32_t size)
{
    int result = ARM_UC_FLASHIAP_FAIL;

    uint32_t sector_aligned_start_address = arm_uc_flashiap_align_to_sector(address, true);
    uint32_t end_address = address + size;

    /* align end address to closest boundary, rounded up */
    uint32_t sector_aligned_end_address = arm_uc_flashiap_align_to_sector(end_address, false);

    /* check if address is sector aligned; a sector aligned address is by definition within bounds */
    if (address == sector_aligned_start_address) {

        uint32_t erase_address = address;
        result = ARM_UC_FLASHIAP_SUCCESS;

        /* erase one sector at a time */
        while ((erase_address < sector_aligned_end_address) && (result == ARM_UC_FLASHIAP_SUCCESS)) {

            /* erase current sector */
            result = flash_erase_sector(&arm_uc_flash_obj, erase_address);

            /* set next erase address */
            uint32_t sector_size = flash_get_sector_size(&arm_uc_flash_obj, erase_address);
            erase_address += sector_size;
        }
    }

    return result;
}

int32_t arm_uc_flashiap_program(const uint8_t *buffer, uint32_t address, uint32_t size)
{
    int result = ARM_UC_FLASHIAP_FAIL;

    /* check if buffer is valid */
    if (buffer) {

        uint32_t flash_start_address = flash_get_start_address(&arm_uc_flash_obj);
        uint32_t flash_size = flash_get_size(&arm_uc_flash_obj);
        uint32_t flash_end_address = flash_start_address + flash_size;

        /* check addresses are within bounds */
        if ((flash_start_address <= address) &&
                ((address + size) <= flash_end_address) &&
                (size <= flash_size)) {

            uint32_t page_size = flash_get_page_size(&arm_uc_flash_obj);

            /* check address and size are page aligned */
            if (((address % page_size) == 0) && ((size % page_size) == 0)) {

                uint32_t index = 0;
                result = ARM_UC_FLASHIAP_SUCCESS;

                /* program one page at a time */
                while ((index < size) && (result == ARM_UC_FLASHIAP_SUCCESS)) {

                    result = flash_program_page(&arm_uc_flash_obj, address + index, buffer + index, page_size);
                    index += page_size;
                }
            }
        }
    }

    return result;
}

int32_t arm_uc_flashiap_read(uint8_t *buffer, uint32_t address, uint32_t size)
{
    return flash_read(&arm_uc_flash_obj, address, buffer, size);
}

uint32_t arm_uc_flashiap_get_page_size(void)
{
    return flash_get_page_size(&arm_uc_flash_obj);
}

uint32_t arm_uc_flashiap_get_sector_size(uint32_t address)
{
    return flash_get_sector_size(&arm_uc_flash_obj, address);
}

uint32_t arm_uc_flashiap_get_flash_size(void)
{
    return flash_get_size(&arm_uc_flash_obj);
}

uint32_t arm_uc_flashiap_get_flash_start(void)
{
    return flash_get_start_address(&arm_uc_flash_obj);
}

uint8_t arm_uc_flashiap_get_erase_value(void)
{
    return flash_get_erase_value(&arm_uc_flash_obj);
}

uint32_t arm_uc_flashiap_align_to_sector(uint32_t address, bool round_down)
{
    /* default to returning the beginning of the flash */
    uint32_t sector_aligned_address = flash_get_start_address(&arm_uc_flash_obj);
    uint32_t flash_end_address = sector_aligned_address + flash_get_size(&arm_uc_flash_obj);

    /* addresses out of bounds are pinned to the flash boundaries */
    if (address >= flash_end_address) {

        sector_aligned_address = flash_end_address;

        /* for addresses within bounds step through the sector map */
    } else if (address > sector_aligned_address) {

        uint32_t sector_size = 0;

        /* add sectors from start of flash until we exceed the required address
           we cannot assume uniform sector size as in some mcu sectors have
           drastically different sizes
        */
        while (sector_aligned_address < address) {
            sector_size = flash_get_sector_size(&arm_uc_flash_obj, sector_aligned_address);
            sector_aligned_address += sector_size;
        }

        /* if round down to nearest sector, remove the last sector from address
           if not already aligned
        */
        if (round_down && (sector_aligned_address != address)) {
            sector_aligned_address -= sector_size;
        }
    }

    return sector_aligned_address;
}

uint32_t arm_uc_flashiap_round_up_to_page_size(uint32_t size)
{
    uint32_t page_size = flash_get_page_size(&arm_uc_flash_obj);

    if (size != 0) {
        size = ((size - 1) / page_size + 1) * page_size;
    }

    return size;
}

#endif /* TARGET_LIKE_MBED */
#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
