// ----------------------------------------------------------------------------
// Copyright 2017-2018 ARM Ltd.
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
#if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) && (ARM_UC_FEATURE_PAL_BLOCKDEVICE == 1)

#define __STDC_FORMAT_MACROS

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice.h"
#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_platform.h"

#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"

#include <inttypes.h>

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

#if (MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE == 0)
#error Update client storage size cannot be zero.
#endif

/* Check that the statically allocated buffers are aligned with the block size */
#define ARM_UC_PAL_ONE_BUFFER (ARM_UC_BUFFER_SIZE / 2)
#define ARM_UC_PAL_PAGES (ARM_UC_PAL_ONE_BUFFER / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)

#if !((ARM_UC_PAL_PAGES * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) == ARM_UC_PAL_ONE_BUFFER)
#error Update client buffer must be divisible by the block page size
#endif

static ARM_UC_PAAL_UPDATE_SignalEvent_t pal_blockdevice_event_handler = NULL;
static uint32_t pal_blockdevice_firmware_size = 0;
static uint32_t pal_blockdevice_page_size = 0;
static uint32_t pal_blockdevice_sector_size = 0;
static uint32_t pal_blockdevice_hdr_size = 0;

static void pal_blockdevice_signal_internal(uint32_t event)
{
    if (pal_blockdevice_event_handler) {
        pal_blockdevice_event_handler(event);
    }
}

/**
 * @brief Round size up to nearest page
 *
 * @param size The size that need to be rounded up
 * @return Returns the size rounded up to the nearest page
 */
static uint32_t pal_blockdevice_round_up_to_page(uint32_t size)
{
    uint32_t round_up = 0;
    /* 0 is an aligned address and math operation below would not return 0.
       It would return pal_blockdevice_page_size*/
    if (size != 0) {
        round_up = ((size - 1) / pal_blockdevice_page_size + 1) * pal_blockdevice_page_size;
    }
    return round_up;
}

/**
 * @brief Round size down to nearest page
 *
 * @param size The size that need to be rounded up
 * @return Returns the size rounded up to the nearest page
 */
static uint32_t pal_blockdevice_round_down_to_page(uint32_t size)
{
    return (size / pal_blockdevice_page_size) * pal_blockdevice_page_size;
}

/**
 * @brief Align size up to sector size
 *
 * @param size The size that need to be rounded up
 * @return Returns the size aligned to sector size
 */
static uint32_t pal_blockdevice_round_up_to_sector(uint32_t size)
{
    uint32_t round_up = 0;
    /* 0 is an aligned address and math operation below would not return 0.
       It would return pal_blockdevice_sector_size*/
    if (size != 0) {
        round_up = ((size - 1) / pal_blockdevice_sector_size + 1) * pal_blockdevice_sector_size;
    }
    return round_up;
}

/**
 * @brief Align size down to sector size
 *
 * @param size The size that need to be rounded up
 * @return Returns the size aligned to sector boundary
 */
static uint32_t pal_blockdevice_round_down_to_sector(uint32_t size)
{
    return (size / pal_blockdevice_sector_size) * pal_blockdevice_sector_size;
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
static arm_uc_error_t pal_blockdevice_get_slot_addr_size(uint32_t slot_id,
                                                         uint32_t *slot_addr,
                                                         uint32_t *slot_size)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if ((slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) &&
            (slot_addr != NULL) &&
            (slot_size != NULL)) {
        /* find the start address of the whole storage area. It needs to be aligned to
           sector boundary and we cannot go outside user defined storage area, hence
           rounding up to sector boundary */
        uint32_t storage_start_addr = pal_blockdevice_round_up_to_sector(
                                          MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS);
        /* find the end address of the whole storage area. It needs to be aligned to
           sector boundary and we cannot go outside user defined storage area, hence
           rounding down to sector boundary */
        uint32_t storage_end_addr = pal_blockdevice_round_down_to_sector(
                                        MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS + \
                                        MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE);
        /* find the maximum size each slot can have given the start and end, without
           considering the alignment of individual slots */
        uint32_t max_slot_size = (storage_end_addr - storage_start_addr) / \
                                 MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
        /* find the start address of slot. It needs to align to sector boundary. We
           choose here to round down at each slot boundary */
        *slot_addr = storage_start_addr + pal_blockdevice_round_down_to_sector(
                         slot_id * max_slot_size);
        /* Rounding down slot size to sector boundary same as
           the slot start address so that we make sure two slot don't overlap */
        *slot_size  = pal_blockdevice_round_down_to_sector(max_slot_size);
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Initialize the underlying storage and set the callback handler.
 *
 * @param callback Function pointer to event handler.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_BlockDevice_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (callback) {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Initialize");

        int status = arm_uc_blockdevice_init();
        pal_blockdevice_page_size  = arm_uc_blockdevice_get_program_size();
        pal_blockdevice_sector_size = arm_uc_blockdevice_get_erase_size();
        pal_blockdevice_hdr_size   = pal_blockdevice_round_up_to_page(ARM_UC_EXTERNAL_HEADER_SIZE_V2);

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS) {
            pal_blockdevice_event_handler = callback;
            pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);
            result.code = ERR_NONE;
        }
    }

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_BlockDevice_GetMaxID(void)
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Prepare(uint32_t slot_id,
                                              const arm_uc_firmware_details_t *details,
                                              arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer && buffer->ptr) {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Prepare: %" PRIX32 " %" PRIX64,
                      slot_id, details->size);

        /* encode firmware details in buffer */
        arm_uc_error_t header_status = arm_uc_create_external_header_v2(details,
                                                                        buffer);
        if (header_status.error == ERR_NONE) {
            /* find the size needed to erase. Header is stored contiguous with firmware */
            uint32_t erase_size = pal_blockdevice_round_up_to_sector(pal_blockdevice_hdr_size + \
                                                                     details->size);

            /* find address of slot */
            uint32_t slot_addr = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
            uint32_t slot_size = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
            result = pal_blockdevice_get_slot_addr_size(slot_id, &slot_addr, &slot_size);

            UC_PAAL_TRACE("erase: %" PRIX32 " %" PRIX32 " %" PRIX32, slot_addr, erase_size, slot_size);

            int status = ARM_UC_BLOCKDEVICE_FAIL;
            if (result.error == ERR_NONE) {
                if (erase_size <= slot_size) {
                    /* erase */
                    status = arm_uc_blockdevice_erase(slot_addr, erase_size);
                } else {
                    UC_PAAL_ERR_MSG("not enough space for firmware image");
                    result.code = PAAL_ERR_FIRMWARE_TOO_LARGE;
                }
            }

            if (status == ARM_UC_BLOCKDEVICE_SUCCESS) {
                /* write header */
                status = arm_uc_blockdevice_program(buffer->ptr,
                                                    slot_addr,
                                                    pal_blockdevice_hdr_size);

                if (status == ARM_UC_BLOCKDEVICE_SUCCESS) {
                    /* set return code */
                    result.code = ERR_NONE;

                    /* store firmware size in global */
                    pal_blockdevice_firmware_size = details->size;

                    /* signal done */
                    pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);
                } else {
                    UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");
                }
            } else {
                UC_PAAL_ERR_MSG("arm_uc_blockdevice_erase failed");
            }
        } else {
            UC_PAAL_ERR_MSG("arm_uc_create_external_header_v2 failed");
        }
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Write(uint32_t slot_id,
                                            uint32_t offset,
                                            const arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr) {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Write: %" PRIX32 " %" PRIX32 " %" PRIX32,
                      slot_id, offset, buffer->size);
        int status = ARM_UC_BLOCKDEVICE_SUCCESS;

        /* find address of slot */
        uint32_t slot_addr = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
        uint32_t slot_size = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
        result = pal_blockdevice_get_slot_addr_size(slot_id, &slot_addr, &slot_size);
        uint32_t physical_address = slot_addr + pal_blockdevice_hdr_size + offset;

        /* check that we are not writing too much */
        uint32_t aligned_size = 0;
        if (pal_blockdevice_firmware_size < offset + buffer->size) {
            UC_PAAL_ERR_MSG("programming more than firmware size %" PRIu32
                            " < %" PRIu32 " + %" PRIu32,
                            pal_blockdevice_firmware_size, offset, buffer->size);
        } else if ((pal_blockdevice_firmware_size > offset + buffer->size) &&
                   (buffer->size % pal_blockdevice_page_size != 0)) {
            UC_PAAL_ERR_MSG("program size %" PRIu32 " does not align to page size %" PRIu32,
                            buffer->size, pal_blockdevice_page_size);
        } else if (pal_blockdevice_firmware_size == offset + buffer->size) {
            /* last chunk write page aligned data first */
            aligned_size = pal_blockdevice_round_down_to_page(buffer->size);
        } else {
            aligned_size = buffer->size;
        }

        /* aligned write */
        if (result.error == ERR_NONE && aligned_size > 0) {
            status = arm_uc_blockdevice_program(buffer->ptr,
                                                physical_address,
                                                aligned_size);
            if (status == ARM_UC_BLOCKDEVICE_FAIL) {
                UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");
            }
        }

        /* last chunk write remainder */
        uint32_t remainder_size = buffer->size - aligned_size;

        if ((status == ARM_UC_BLOCKDEVICE_SUCCESS) && (remainder_size > 0)) {
            /* check if it is safe to use buffer, i.e. buffer is larger than a page */
            if (buffer->size_max >= pal_blockdevice_page_size) {
                memmove(buffer->ptr, &(buffer->ptr[aligned_size]), remainder_size);
                status = arm_uc_blockdevice_program(buffer->ptr,
                                                    physical_address + aligned_size,
                                                    pal_blockdevice_page_size);
            } else {
                UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");

                status = ARM_UC_BLOCKDEVICE_FAIL;
            }
        }

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS) {
            /* set return code */
            result.code = ERR_NONE;

            /* signal done */
            pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);
        } else {
            UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");
        }
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Finalize(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Finalize");

    pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Read(uint32_t slot_id,
                                           uint32_t offset,
                                           arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr) {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Read: %" PRIX32 " %" PRIX32 " %" PRIX32,
                      slot_id, offset, buffer->size);

        /* find address of slot */
        uint32_t slot_addr = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
        uint32_t slot_size = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
        result = pal_blockdevice_get_slot_addr_size(slot_id,
                                                    &slot_addr,
                                                    &slot_size);
        uint32_t physical_address = slot_addr + pal_blockdevice_hdr_size + offset;
        uint32_t read_size = pal_blockdevice_round_up_to_page(buffer->size);
        int32_t status = ARM_UC_BLOCKDEVICE_FAIL;

        if (read_size <= buffer->size_max) {
            status = arm_uc_blockdevice_read(buffer->ptr,
                                             physical_address,
                                             read_size);
        }

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS) {
            /* set return code */
            result.code = ERR_NONE;

            /* signal done */
            pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_READ_DONE);
        } else {
            UC_PAAL_ERR_MSG("arm_uc_blockdevice_read failed");
        }
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Activate(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Activate");

    pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);

    return result;
}

/**
 * @brief Get firmware details for the firmware image in the slot passed.
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param slot_id Storage location ID.
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_BlockDevice_GetFirmwareDetails(
    uint32_t slot_id,
    arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_GetFirmwareDetails");

        /* find address of slot */
        uint32_t slot_addr = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
        uint32_t slot_size = ARM_UC_BLOCKDEVICE_INVALID_SIZE;
        result = pal_blockdevice_get_slot_addr_size(slot_id, &slot_addr, &slot_size);
        uint8_t buffer[pal_blockdevice_hdr_size];

        int status = arm_uc_blockdevice_read(buffer,
                                             slot_addr,
                                             pal_blockdevice_hdr_size);

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS) {
            result = arm_uc_parse_external_header_v2(buffer, details);

            if (result.error == ERR_NONE) {
                /* signal done */
                pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE);
            } else {
                UC_PAAL_ERR_MSG("arm_uc_parse_external_header_v2 failed");
            }
        } else {
            UC_PAAL_ERR_MSG("arm_uc_blockdevice_read failed");
        }
    }

    return result;
}

#endif // #if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE)
