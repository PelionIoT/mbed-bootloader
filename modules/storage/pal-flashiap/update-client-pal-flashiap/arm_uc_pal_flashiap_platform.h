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

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ARM_UC_FLASHIAP_SUCCESS = 0,
    ARM_UC_FLASHIAP_FAIL    = -1
};

#define ARM_UC_FLASH_INVALID_SIZE 0xFFFFFFFF

/** Initialize a flash IAP device
 *
 *  Should be called once per lifetime of the object.
 *  @return 0 on success or a negative error code on failure
 */
int32_t arm_uc_flashiap_init(void);

/** Erase sectors
 *
 *  The state of an erased sector is undefined until it has been programmed
 *
 *  @param address  Address of a sector to begin erasing, must be a multiple of the sector size
 *  @param size     Size to erase in bytes, must be a multiple of the sector size
 *  @return         0 on success, negative error code on failure
 */
int32_t arm_uc_flashiap_erase(uint32_t address, uint32_t size);

/** Program data to pages
 *
 *  The sectors must have been erased prior to being programmed
 *
 *  @param buffer   Buffer of data to be written
 *  @param address  Address of a page to begin writing to, must be a multiple of program and sector sizes
 *  @param size     Size to write in bytes, must be a multiple of program and sector sizes
 *  @return         0 on success, negative error code on failure
 */
int32_t arm_uc_flashiap_program(const uint8_t *buffer,
                                uint32_t address,
                                uint32_t size);

/** Read data from a flash device.
 *
 *  This method invokes memcpy - reads number of bytes from the address
 *
 *  @param buffer   Buffer to write to
 *  @param address  Flash address to begin reading from
 *  @param size     Size to read in bytes
 *  @return         0 on success, negative error code on failure
 */
int32_t arm_uc_flashiap_read(uint8_t *buffer,
                             uint32_t address,
                             uint32_t size);

/** Get the program page size
 *
 *  @return Size of a program page in bytes
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
#ifdef __cplusplus
}
#endif

#endif
