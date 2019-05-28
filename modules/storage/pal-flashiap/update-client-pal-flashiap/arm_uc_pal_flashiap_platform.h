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

#ifndef ARM_UC_PAL_FLASHIAP_PLATFORM_H
#define ARM_UC_PAL_FLASHIAP_PLATFORM_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ARM_UC_FLASHIAP_SUCCESS = 0,
    ARM_UC_FLASHIAP_FAIL    = -1
};

#define ARM_UC_FLASH_INVALID_SIZE 0xFFFFFFFF

/** Initialize flash device
 *
 *  @return ARM_UC_FLASHIAP_SUCCESS on success
 *          ARM_UC_FLASHIAP_FAIL on failure
 */
int32_t arm_uc_flashiap_init(void);

/** Free flash device
 *
 *  @return ARM_UC_FLASHIAP_SUCCESS on success
 *          ARM_UC_FLASHIAP_FAIL on failure
 */
int32_t arm_uc_flashiap_free(void);

/** Erase sectors
 *
 *  Erase all sectors starting at the provided address until the
 *  size has been reached.
 *
 *  If the erase size is not sector aligned the sector containing
 *  the end of the erase request will be erased as well. This ensures
 *  the same result and user experience without the extra step of
 *  calculating a sector aligned erase size.
 *
 *  @param address  Address of a sector to begin erasing,
 *                  must be aligned to an erase sector
 *  @param size     Size to erase in bytes
 *  @return         ARM_UC_FLASHIAP_SUCCESS on success
 *                  ARM_UC_FLASHIAP_FAIL on failure
 */
int32_t arm_uc_flashiap_erase(uint32_t address, uint32_t size);

/** Program data
 *
 *  Write the number of size bytes from the buffer to the address
 *  in flash.
 *
 *  Address and size must be aligned to the page address. The data
 *  being written can span multiple pages and even sectors, but
 *  the sectors being written to musth have been erased prior
 *  to being programmed.
 *
 *  @param buffer   Buffer of data to be written
 *  @param address  Address of a page to begin writing to,
 *                  must be a multiple of program page size
 *  @param size     Size to write in bytes, must be a multiple
 *                  program page size
 *  @return         ARM_UC_FLASHIAP_SUCCESS on success
 *                  ARM_UC_FLASHIAP_FAIL on failure
 */
int32_t arm_uc_flashiap_program(const uint8_t *buffer,
                                uint32_t address,
                                uint32_t size);

/** Read data from flash device.
 *
 *  @param buffer   Buffer to write to
 *  @param address  Flash address to begin reading from
 *  @param size     Size to read in bytes
 *  @return         ARM_UC_FLASHIAP_SUCCESS on success
 *                  ARM_UC_FLASHIAP_FAIL on failure
 */
int32_t arm_uc_flashiap_read(uint8_t *buffer,
                             uint32_t address,
                             uint32_t size);

/** Get the program page size
 *
 *  @return         Size of a program page in bytes
 */
uint32_t arm_uc_flashiap_get_page_size(void);

/** Get the sector size at the defined address
 *
 *  Sector size might differ at address ranges.
 *  An example <0-0x1000, sector size=1024; 0x10000-0x20000, size=2048>
 *
 *  @param address  Address of or inside the sector to query
 *  @return         Size of a sector in bytes
 */
uint32_t arm_uc_flashiap_get_sector_size(uint32_t address);

/** Get the flash size
 *
 *  @return         Size of the flash in bytes
 */
uint32_t arm_uc_flashiap_get_flash_size(void);


/** Get the flash start address
 *
 *  @return         Start address of the flash
 */
uint32_t arm_uc_flashiap_get_flash_start(void);

/** Get the flash erase value
 *
 * @return          The flash erase value
 */
uint8_t arm_uc_flashiap_get_erase_value(void);

/** Align address up/down to sector boundary
 *
 *  Addresses outside flash will be pinned to either the start
 *  or the end of flash.
 *
 *  Addresses on boundaries will not be rounded up/down.
 *
 * @param address   The address that need to be rounded up/down
 * @param round_down If the value is true, will align down to sector
                    boundary otherwise align up.
 * @return Returns the address aligned to sector boundary
 */
uint32_t arm_uc_flashiap_align_to_sector(uint32_t address, bool round_down);

/** Round size up to nearest page
 *
 * @param size      The size that need to be rounded up
 * @return          Returns the size rounded up to the nearest page
 */
uint32_t arm_uc_flashiap_round_up_to_page_size(uint32_t size);

#ifdef __cplusplus
}
#endif

#endif
