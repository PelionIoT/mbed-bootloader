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

#include "update-client-pal-flashiap/arm_uc_pal_flashiap.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"
#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"

#include <inttypes.h>
#include <stddef.h>

#ifndef MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS
#define MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS
#define MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE 1
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS 1
#endif

/* consistency check */
#if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE == 0)
#error Update client storage page cannot be zero.
#endif

#if (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS == 0)
#error Update client storage locations must be at least 1.
#endif

/* Check that the statically allocated buffers are aligned with the block size */
#define ARM_UC_PAL_ONE_BUFFER (ARM_UC_BUFFER_SIZE / 2)
#define ARM_UC_PAL_PAGES (ARM_UC_PAL_ONE_BUFFER / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)

#if !((ARM_UC_PAL_PAGES * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) == ARM_UC_PAL_ONE_BUFFER)
#error Update client buffer must be divisible by the block page size
#endif

/* Use internal header format because we are using internal flash and
   is assumed to be trusted */
#define ARM_UC_PAL_HEADER_SIZE (uint32_t) ARM_UC_INTERNAL_HEADER_SIZE_V2

static uint64_t arm_uc_pal_flashiap_firmware_size = 0;

static void (*arm_uc_pal_flashiap_callback)(uint32_t) = NULL;

static void arm_uc_pal_flashiap_signal_internal(uint32_t event)
{
    if (arm_uc_pal_flashiap_callback) {
        arm_uc_pal_flashiap_callback(event);
    }
}

/**
 * @brief Align address up/down to sector boundary
 *
 * @param addr The address that need to be rounded up
 * @param round_down if the value is 1, will align down to sector
                     boundary otherwise align up.
 * @return Returns the address aligned to sector boundary
 */
static uint32_t arm_uc_pal_flashiap_align_to_sector(uint32_t addr, int8_t round_down)
{
    uint32_t sector_start_addr = arm_uc_flashiap_get_flash_start();

    /* check the address is pointing to internal flash */
    if ((addr > sector_start_addr + arm_uc_flashiap_get_flash_size()) ||
            (addr < sector_start_addr)) {
        return ARM_UC_FLASH_INVALID_SIZE;
    }

    /* add sectors from start of flash until exeeced the required address
       we cannot assume uniform sector size as in some mcu sectors have
       drastically different sizes */
    uint32_t sector_size = ARM_UC_FLASH_INVALID_SIZE;
    while (sector_start_addr < addr) {
        sector_size = arm_uc_flashiap_get_sector_size(sector_start_addr);
        if (sector_size != ARM_UC_FLASH_INVALID_SIZE) {
            sector_start_addr += sector_size;
        } else {
            return ARM_UC_FLASH_INVALID_SIZE;
        }
    }

    /* if round down to nearest section, remove the last sector from addr */
    if (round_down != 0 && sector_start_addr > addr) {
        sector_start_addr -= sector_size;
    }

    return sector_start_addr;
}

/**
 * @brief Round size up to nearest page
 *
 * @param size The size that need to be rounded up
 * @return Returns the size rounded up to the nearest page
 */
static uint32_t arm_uc_pal_flashiap_round_up_to_page_size(uint32_t size)
{
    uint32_t page_size = arm_uc_flashiap_get_page_size();

    if (size != 0) {
        size = ((size - 1) / page_size + 1) * page_size;
    }

    return size;
}

/**
 * @brief Get the physicl slot address and size given slot_id
 *
 * @param slot_id Storage location ID.
 * @param slot_addr the slot address is returned in this pointer
 * @param slot_size the slot size is returned in this pointer
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
static arm_uc_error_t arm_uc_pal_flashiap_get_slot_addr_size(uint32_t slot_id,
                                                             uint32_t *slot_addr,
                                                             uint32_t *slot_size)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    /* find the start address of the whole storage area. It needs to be aligned to
       sector boundary and we cannot go outside user defined storage area, hence
       rounding up to sector boundary */
    uint32_t storage_start_addr = arm_uc_pal_flashiap_align_to_sector(
                                      MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS, 0);
    /* find the end address of the whole storage area. It needs to be aligned to
       sector boundary and we cannot go outside user defined storage area, hence
       rounding down to sector boundary */
    uint32_t storage_end_addr = arm_uc_pal_flashiap_align_to_sector(
                                    MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS + \
                                    MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE, 1);
    /* find the maximum size each slot can have given the start and end, without
       considering the alignment of individual slots */
    uint32_t max_slot_size = (storage_end_addr - storage_start_addr) / \
                             MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
    /* find the start address of slot. It needs to align to sector boundary. We
       choose here to round down at each slot boundary */
    uint32_t slot_start_addr = arm_uc_pal_flashiap_align_to_sector(
                                   storage_start_addr + \
                                   slot_id * max_slot_size, 1);
    /* find the end address of the slot, rounding down to sector boundary same as
       the slot start address so that we make sure two slot don't overlap */
    uint32_t slot_end_addr = arm_uc_pal_flashiap_align_to_sector(
                                 slot_start_addr + \
                                 max_slot_size, 1);

    /* Any calculation above might result in an invalid address. */
    if ((storage_start_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (storage_end_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (slot_start_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (slot_end_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (slot_id >= MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS)) {
        UC_PAAL_ERR_MSG("Aligning fw storage slot to erase sector failed"
                        " storage_start_addr %" PRIX32 " slot_start_addr %" PRIX32
                        " max_slot_size %" PRIX32, storage_start_addr, slot_start_addr,
                        max_slot_size);
        *slot_addr = ARM_UC_FLASH_INVALID_SIZE;
        *slot_size = ARM_UC_FLASH_INVALID_SIZE;
    } else {
        *slot_addr = slot_start_addr;
        *slot_size = slot_end_addr - slot_start_addr;
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Initialise the flash IAP API
 *
 * @param callback function pointer to the PAAL event handler
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Initialize(void (*callback)(uint32_t))
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    int32_t status = arm_uc_flashiap_init();

    if (status == ARM_UC_FLASHIAP_SUCCESS) {
        arm_uc_pal_flashiap_callback = callback;
        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);

        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_FlashIAP_GetMaxID(void)
{
    return MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
}

/**
 * @brief Prepare the storage layer for a new firmware image.
 * @details The storage location is set up to receive an image with
 *          the details passed in the details struct.
 *
 * @param slot_id Storage location ID.
 * @param details Pointer to a struct with firmware details.
 * @param buffer Temporary buffer for formatting and storing metadata.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Prepare(uint32_t slot_id,
                                           const arm_uc_firmware_details_t *details,
                                           arm_uc_buffer_t *buffer)
{
    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Prepare slot_id %" PRIu32 " details %p buffer %p",
                  slot_id, details, buffer);

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t erase_size = ARM_UC_FLASH_INVALID_SIZE;

    /* validate input */
    if (details && buffer && buffer->ptr && \
            slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) {
        UC_PAAL_TRACE("FW size %" PRIu64, details->size);
        result.error = ERR_NONE;
    } else {
        UC_PAAL_TRACE("Input validation failed");
    }

    /* calculate space for new firmware */
    if (result.error == ERR_NONE) {
        /* find slot start address */
        result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id, &slot_addr, &slot_size);

        /* find the amount of space that need to be erased */
        erase_size = arm_uc_pal_flashiap_align_to_sector(
                         slot_addr + \
                         arm_uc_pal_flashiap_round_up_to_page_size(details->size) + \
                         arm_uc_pal_flashiap_round_up_to_page_size(ARM_UC_PAL_HEADER_SIZE),
                         0) - slot_addr;

        if ((result.error == ERR_NONE) && (erase_size > slot_size)) {
            result.code = PAAL_ERR_FIRMWARE_TOO_LARGE;
            UC_PAAL_ERR_MSG("Firmware too large! required %" PRIX32 " available: %" PRIX32,
                            erase_size, slot_size);
        }
    }

    /* erase space for new firmware */
    if (result.error == ERR_NONE) {
        uint32_t erase_addr = slot_addr;
        while (erase_addr < slot_addr + erase_size) {
            uint32_t sector_size = arm_uc_flashiap_get_sector_size(erase_addr);
            UC_PAAL_TRACE("erase: addr %" PRIX32 " size %" PRIX32,
                          erase_addr, sector_size);
            if (sector_size != ARM_UC_FLASH_INVALID_SIZE) {
                int32_t status = arm_uc_flashiap_erase(erase_addr, sector_size);
                if (status == ARM_UC_FLASHIAP_SUCCESS) {
                    erase_addr += sector_size;
                } else {
                    UC_PAAL_ERR_MSG("Flash erase failed with status %" PRIi32, status);
                    result.code = ERR_INVALID_PARAMETER;
                    break;
                }
            } else {
                UC_PAAL_ERR_MSG("Get sector size for addr %" PRIX32 " failed", erase_addr);
                result.code = ERR_INVALID_PARAMETER;
                break;
            }
        }
    }

    /* generate header blob */
    if (result.error == ERR_NONE) {
        result  = arm_uc_create_internal_header_v2(details, buffer);
        if (result.error != ERR_NONE) {
            UC_PAAL_ERR_MSG("arm_uc_create_internal_header_v2 failed");
        }
    }

    /* write header blob */
    if (result.error == ERR_NONE) {
        uint32_t hdr_size = arm_uc_pal_flashiap_round_up_to_page_size(ARM_UC_PAL_HEADER_SIZE);
        UC_PAAL_TRACE("program: %" PRIX32 " %" PRIX32,
                      slot_addr, hdr_size);

        /* write header */
        int32_t status = arm_uc_flashiap_program((const uint8_t *) buffer->ptr,
                                                 slot_addr,
                                                 hdr_size);
        if (status != ARM_UC_FLASHIAP_SUCCESS) {
            /* set return code */
            result.code = ERR_INVALID_PARAMETER;
        }
    }

    if (result.error == ERR_NONE) {
        /* store firmware size in global */
        arm_uc_pal_flashiap_firmware_size = details->size;

        /* signal done */
        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);
    }

    return result;
}

/**
 * @brief Write a fragment to the indicated storage location.
 * @details The storage location must have been allocated using the Prepare
 *          call. The call is expected to write the entire fragment before
 *          signaling completion.
 *
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to where the fragment should be written.
 * @param buffer Pointer to buffer struct with fragment.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Write(uint32_t slot_id,
                                         uint32_t offset,
                                         const arm_uc_buffer_t *buffer)
{
    /* find slot address and size */
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    arm_uc_error_t result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id,
                                                                   &slot_addr,
                                                                   &slot_size);

    if (buffer && buffer->ptr && result.error == ERR_NONE) {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Write: %p %" PRIX32 " %" PRIX32 " %" PRIX32,
                      buffer->ptr, buffer->size, slot_addr, offset);

        /* set default error */
        result.code = ERR_INVALID_PARAMETER;

        /* find physical address of the write */
        uint32_t page_size = arm_uc_flashiap_get_page_size();
        uint32_t hdr_size = arm_uc_pal_flashiap_round_up_to_page_size(ARM_UC_PAL_HEADER_SIZE);
        uint32_t physical_address = slot_addr + hdr_size + offset;
        uint32_t write_size = buffer->size;

        /* if last chunk, pad out to page_size aligned size */
        if ((buffer->size % page_size != 0) &&
                ((offset + buffer->size) >= arm_uc_pal_flashiap_firmware_size) &&
                (arm_uc_pal_flashiap_round_up_to_page_size(buffer->size) <= buffer->size_max)) {
            write_size = arm_uc_pal_flashiap_round_up_to_page_size(buffer->size);
        }

        /* check page alignment of the program address and size */
        if ((write_size % page_size == 0) && (physical_address % page_size == 0)) {
            UC_PAAL_TRACE("programming addr %" PRIX32 " size %" PRIX32,
                          physical_address, write_size);
            int status = arm_uc_flashiap_program((const uint8_t *) buffer->ptr,
                                                 physical_address,
                                                 write_size);
            if (status != ARM_UC_FLASHIAP_SUCCESS) {
                UC_PAAL_ERR_MSG("arm_uc_flashiap_program failed");
            } else {
                result.code = ERR_NONE;
                arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);
            }
        } else {
            UC_PAAL_ERR_MSG("program size %" PRIX32 " or address %" PRIX32
                            " not aligned to page size %" PRIX32, buffer->size,
                            physical_address, page_size);
        }
    } else {
        result.code = ERR_INVALID_PARAMETER;
    }

    return result;
}

/**
 * @brief Close storage location for writing and flush pending data.
 *
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Finalize(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Finalize");

    arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

    return result;
}

/**
 * @brief Read a fragment from the indicated storage location.
 * @details The function will read until the buffer is full or the end of
 *          the storage location has been reached. The actual amount of
 *          bytes read is set in the buffer struct.
 *
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to read from.
 * @param buffer Pointer to buffer struct to store fragment. buffer->size
 *        contains the intended read size.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 *         buffer->size contains actual bytes read on return.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Read(uint32_t slot_id,
                                        uint32_t offset,
                                        arm_uc_buffer_t *buffer)
{
    /* find slot address and size */
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    arm_uc_error_t result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id,
                                                                   &slot_addr,
                                                                   &slot_size);

    if (buffer && buffer->ptr && result.error == ERR_NONE) {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Read: %" PRIX32 " %" PRIX32 " %" PRIX32,
                      slot_id, offset, buffer->size);

        /* find physical address of the read */
        uint32_t read_size = buffer->size;
        uint32_t hdr_size = arm_uc_pal_flashiap_round_up_to_page_size(ARM_UC_PAL_HEADER_SIZE);
        uint32_t physical_address = slot_addr + hdr_size + offset;

        UC_PAAL_TRACE("reading addr %" PRIX32 " size %" PRIX32,
                      physical_address, read_size);

        int status = arm_uc_flashiap_read(buffer->ptr,
                                          physical_address,
                                          read_size);

        if (status == ARM_UC_FLASHIAP_SUCCESS) {
            result.code = ERR_NONE;
            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_READ_DONE);
        } else {
            result.code = ERR_INVALID_PARAMETER;
            UC_PAAL_ERR_MSG("arm_uc_flashiap_read failed");
        }
    } else {
        result.code = ERR_INVALID_PARAMETER;
    }

    return result;
}

/**
 * @brief Set the firmware image in the slot to be the new active image.
 * @details This call is responsible for initiating the process for
 *          applying a new/different image. Depending on the platform this
 *          could be:
 *           * An empty call, if the installer can deduce which slot to
 *             choose from based on the firmware details.
 *           * Setting a flag to indicate which slot to use next.
 *           * Decompressing/decrypting/installing the firmware image on
 *             top of another.
 *
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Activate(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Activate");

    arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);

    return result;
}

/**
 * @brief Get firmware details for the firmware image in the slot passed.
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_GetFirmwareDetails(
    uint32_t slot_id,
    arm_uc_firmware_details_t *details)
{
    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_GetFirmwareDetails");

    /* find slot address and size */
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    arm_uc_error_t result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id,
                                                                   &slot_addr,
                                                                   &slot_size);

    if (details && result.error == ERR_NONE) {
        uint8_t buffer[ARM_UC_PAL_HEADER_SIZE] = { 0 };

        int status = arm_uc_flashiap_read(buffer,
                                          slot_addr,
                                          ARM_UC_PAL_HEADER_SIZE);

        if (status == ARM_UC_FLASHIAP_SUCCESS) {
            result = arm_uc_parse_internal_header_v2(buffer, details);

            if (result.error == ERR_NONE) {
                /* signal done */
                arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE);
            } else {
                UC_PAAL_ERR_MSG("arm_uc_parse_internal_header_v2 failed");
            }
        } else {
            UC_PAAL_ERR_MSG("arm_uc_flashiap_read failed");
        }
    }

    return result;
}

/*****************************************************************************/

arm_uc_error_t ARM_UC_PAL_FlashIAP_GetActiveDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* read details from memory if offset is set */
        if (MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS) {
            /* set default error code */
            result.code = ERR_NOT_READY;

            /* Use flash driver eventhough we are reading from internal flash.
               This will make it easier to use with uVisor.
             */
            uint8_t version_buffer[8] = { 0 };

            /* read metadata magic and version from flash */
            int rc = arm_uc_flashiap_read(version_buffer,
                                          MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                          8);

            if (rc == ARM_UC_FLASHIAP_SUCCESS) {
                /* read out header magic */
                uint32_t headerMagic = arm_uc_parse_uint32(&version_buffer[0]);

                /* read out header magic */
                uint32_t headerVersion = arm_uc_parse_uint32(&version_buffer[4]);

                /* choose version to decode */
                switch (headerVersion) {
                    case ARM_UC_INTERNAL_HEADER_VERSION_V2: {
                        result.code = ERR_NONE;
                        /* Check the header magic */
                        if (headerMagic != ARM_UC_INTERNAL_HEADER_MAGIC_V2) {
                            UC_PAAL_ERR_MSG("firmware header is v2, but does not contain v2 magic");
                            result.code = ERR_NOT_READY;
                        }

                        uint8_t read_buffer[ARM_UC_INTERNAL_HEADER_SIZE_V2] = { 0 };
                        /* Read the rest of the header */
                        if (result.error == ERR_NONE) {
                            rc = arm_uc_flashiap_read(read_buffer,
                                                      MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                                      ARM_UC_INTERNAL_HEADER_SIZE_V2);
                            if (rc != 0) {
                                result.code = ERR_NOT_READY;
                                UC_PAAL_ERR_MSG("failed to read v2 header");
                            }
                        }
                        /* Parse the header */
                        if (result.error == ERR_NONE) {
                            result = arm_uc_parse_internal_header_v2(read_buffer, details);
                            if (result.error != ERR_NONE) {
                                UC_PAAL_ERR_MSG("failed to parse v2 header");
                            }
                        }
                        break;
                    }
                    /*
                     * Other firmware header versions can be supported here.
                     */
                    default: {
                        UC_PAAL_ERR_MSG("unrecognized firmware header version");
                        result.code = ERR_NOT_READY;
                    }
                }
            } else {
                UC_PAAL_ERR_MSG("flash read failed");
            }
        } else {
            /* offset not set - zero out struct */
            memset(details, 0, sizeof(arm_uc_firmware_details_t));

            result.code = ERR_NONE;
        }

        /* signal event if operation was successful */
        if (result.error == ERR_NONE) {
            UC_PAAL_TRACE("callback");

            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);
        }
    }

    return result;
}

/**
 * @brief Get details for the firmware installer.
 * @details This call populates the passed details struct with information
 *          about the firmware installer.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_GetInstallerDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* only read from memory if offset is set */
        if (MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS) {
            uint8_t *arm = (uint8_t *)(MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS +
                                       offsetof(arm_uc_installer_details_t, arm_hash));

            uint8_t *oem = (uint8_t *)(MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS +
                                       offsetof(arm_uc_installer_details_t, oem_hash));

            uint8_t *layout = (uint8_t *)(MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS +
                                          offsetof(arm_uc_installer_details_t, layout));

            /* populate installer details struct */
            memcpy(&details->arm_hash, arm, ARM_UC_SHA256_SIZE);
            memcpy(&details->oem_hash, oem, ARM_UC_SHA256_SIZE);
            details->layout = arm_uc_parse_uint32(layout);
        } else {
            /* offset not set, zero details struct */
            memset(details, 0, sizeof(arm_uc_installer_details_t));
        }

        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);

        result.code = ERR_NONE;
    }

    return result;
}

#endif /* TARGET_LIKE_MBED */
#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
