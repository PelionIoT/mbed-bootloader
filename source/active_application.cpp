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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "active_application.h"
#include "bootloader_common.h"

#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"
#include "update-client-paal/arm_uc_paal_update_api.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"
#include "mbedtls/sha256.h"
#include "mbed.h"

#include <inttypes.h>

bool activeStorageInit(void)
{
    int rc = arm_uc_flashiap_init();

    return (rc == ARM_UC_FLASHIAP_SUCCESS);
}

void activeStorageDeinit(void)
{
    arm_uc_flashiap_free();
}

/**
 * Read the metadata header of the active image from internal flash
 * @param  headerP
 *             Caller-allocated header structure.
 * @return true if the read succeeds.
 */
bool readActiveFirmwareHeader(arm_uc_firmware_details_t *details)
{
    bool result = false;

    if (details) {
        /* clear most recent UCP event */
        event_callback = CLEAR_EVENT;

        /* get active firmware details using UCP */
        arm_uc_error_t status = MBED_CLOUD_CLIENT_UPDATE_STORAGE.GetActiveFirmwareDetails(details);

        /* if the call was accepted,
           the event will indicate if the call succeeded
        */
        if (status.error == ERR_NONE) {
            /* wait until the event has been set */
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }

            /* mark the firmware details as valid if so indicated by the event */
            if (event_callback == ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE) {
                result = true;
            }
        }
    }

    return result;
}

/**
 * Verify the integrity of the Active application
 * @detail Read the firmware in the ACTIVE app region and compute its hash.
 *         Compare the computed hash with the one given in the header
 *         to verify the ACTIVE firmware integrity
 * @param  headerP
 *             Caller-allocated header structure containing the hash and size
 *             of the firmware.
 * @return SUCCESS if the validation succeeds
 *         EMPTY   if no active application is present
 *         ERROR   if the validation fails
 */
int checkActiveApplication(arm_uc_firmware_details_t *details)
{
    int result = RESULT_ERROR;

    if (details) {
        /* Read header and verify that it is valid */
        bool headerValid = readActiveFirmwareHeader(details);

        /* calculate hash if header is valid and slot is not empty */
        if ((headerValid) && (details->size > 0)) {
            uint32_t appStart = MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS;

            /* initialize hashing facility */
            mbedtls_sha256_context mbedtls_ctx;
            mbedtls_sha256_init(&mbedtls_ctx);
            mbedtls_sha256_starts(&mbedtls_ctx, 0);

            uint8_t SHA[SIZEOF_SHA256] = { 0 };
            uint32_t remaining = details->size;
            int32_t status = ARM_UC_FLASHIAP_SUCCESS;

            /* read full image */
            while ((remaining > 0) && (status == ARM_UC_FLASHIAP_SUCCESS)) {
                /* read full buffer or what is remaining */
                uint32_t readSize = (remaining > BUFFER_SIZE) ?
                                    BUFFER_SIZE : remaining;

                /* read buffer using FlashIAP API for portability */
                status = arm_uc_flashiap_read(buffer_array,
                                              appStart + (details->size - remaining),
                                              readSize);

                /* update hash */
                mbedtls_sha256_update(&mbedtls_ctx, buffer_array, readSize);

                /* update remaining bytes */
                remaining -= readSize;

#if defined(SHOW_PROGRESS_BAR) && SHOW_PROGRESS_BAR == 1
                printProgress(details->size - remaining,
                              details->size);
#endif
            }

            /* finalize hash */
            mbedtls_sha256_finish(&mbedtls_ctx, SHA);
            mbedtls_sha256_free(&mbedtls_ctx);

            /* compare calculated hash with hash from header */
            int diff = memcmp(details->hash, SHA, SIZEOF_SHA256);

            if (diff == 0) {
                result = RESULT_SUCCESS;
            } else {
                printSHA256(details->hash);
                printSHA256(SHA);
            }
        } else if ((headerValid) && (details->size == 0)) {
            /* header is valid but application size is 0 */
            result = RESULT_EMPTY;
        }
    }

    return result;
}

uint32_t getSectorAlignedSize(uint32_t addr, uint32_t size)
{
    /* Find the exact end sector boundary. Some platforms have different sector
       sizes from sector to sector. Hence we count the sizes 1 sector at a time here */
    uint32_t erase_address = addr;
    while (erase_address < (addr + size)) {
        erase_address += arm_uc_flashiap_get_sector_size(erase_address);
    }

    return erase_address - addr;
}

/**
 * Wipe the ACTIVE firmware region in the flash
 */
bool eraseActiveFirmware(uint32_t firmwareSize)
{
    uint32_t fw_metadata_hdr_size = getSectorAlignedSize(FIRMWARE_METADATA_HEADER_ADDRESS,
                                    ARM_UC_INTERNAL_HEADER_SIZE_V2);
    uint32_t size_needed = 0;
    uint32_t erase_start_addr = 0;
    int result = ARM_UC_FLASHIAP_SUCCESS;

    if (((FIRMWARE_METADATA_HEADER_ADDRESS + fw_metadata_hdr_size) < \
            (MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS)) || \
            (FIRMWARE_METADATA_HEADER_ADDRESS > MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS)) {
        /* header separate from app */
        boot_debug("[DBG ] Erasing header separately from active application\r\n");

        /* erase header section first */
        result = arm_uc_flashiap_erase(FIRMWARE_METADATA_HEADER_ADDRESS, fw_metadata_hdr_size);

        /* setup erase of the application region */
        size_needed = firmwareSize;
        erase_start_addr = MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS;
    } else { /* header contiguous with app */
        /* setup erase of the header + application region */
        size_needed = (MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS - FIRMWARE_METADATA_HEADER_ADDRESS) + firmwareSize;
        erase_start_addr = FIRMWARE_METADATA_HEADER_ADDRESS;
    }

    if (result == ARM_UC_FLASHIAP_SUCCESS) {
        result = ARM_UC_FLASHIAP_FAIL;
        uint32_t erase_end_addr = erase_start_addr + \
                                  getSectorAlignedSize(erase_start_addr,
                                          size_needed);
        uint32_t max_end_addr = MBED_CONF_MBED_BOOTLOADER_MAX_APPLICATION_SIZE + \
                                MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS;
        /* check that the erase will not exceed MBED_CONF_MBED_BOOTLOADER_MAX_APPLICATION_SIZE */
        if (erase_end_addr <= max_end_addr) {
            result = arm_uc_flashiap_erase(erase_start_addr, size_needed);
        } else {
            boot_debug("[DBG ] Firmware size rounded up to the nearest sector boundary is larger than the maximum application size\r\n");
        }
    }

    return (result == ARM_UC_FLASHIAP_SUCCESS);
}

bool writeActiveFirmwareHeader(arm_uc_firmware_details_t *details)
{
    int result = ARM_UC_FLASHIAP_FAIL;

    if (details) {
        /* round up program size to nearest page size */
        const uint32_t pageSize = arm_uc_flashiap_get_page_size();
        const uint32_t programSize = (ARM_UC_INTERNAL_HEADER_SIZE_V2 + pageSize - 1)
                                     / pageSize * pageSize;
        const uint32_t fw_metadata_hdr_size = \
                                              getSectorAlignedSize(FIRMWARE_METADATA_HEADER_ADDRESS,
                                                      ARM_UC_INTERNAL_HEADER_SIZE_V2);

        /* coverity[no_escape] */
        MBED_BOOTLOADER_ASSERT((programSize <= BUFFER_SIZE),
                               "Header program size %" PRIu32 " bigger than buffer %d\r\n",
                               programSize, BUFFER_SIZE);

        /* coverity[no_escape] */
        MBED_BOOTLOADER_ASSERT((programSize <= fw_metadata_hdr_size),
                               "Header program size %" PRIu32 " bigger than expected header %" PRIu32 "\r\n",
                               programSize, fw_metadata_hdr_size);

        /* pad buffer to 0xFF */
        memset(buffer_array, 0xFF, programSize);

        /* create internal header in temporary buffer */
        arm_uc_buffer_t output_buffer = {
            .size_max = BUFFER_SIZE,
            .size     = 0,
            .ptr      = buffer_array
        };

        arm_uc_error_t status = arm_uc_create_internal_header_v2(details,
                                &output_buffer);

        if ((status.error == ERR_NONE) &&
                (output_buffer.size == ARM_UC_INTERNAL_HEADER_SIZE_V2)) {
            /* write header using FlashIAP API */
            result = arm_uc_flashiap_program(buffer_array,
                                             FIRMWARE_METADATA_HEADER_ADDRESS,
                                             programSize);
        }
    }

    return (result == ARM_UC_FLASHIAP_SUCCESS);
}

bool writeActiveFirmware(uint32_t index, arm_uc_firmware_details_t *details)
{
    bool result = false;

    if (details) {
        const uint32_t pageSize = arm_uc_flashiap_get_page_size();

        /* we require app_start_addr fall on a page size boundary */
        uint32_t app_start_addr = MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS;

        /* coverity[no_escape] */
        MBED_BOOTLOADER_ASSERT((app_start_addr % pageSize) == 0,
                               "Application (0x%" PRIX32 ") does not start on a "
                               "page size (0x%" PRIX32 ") aligned address\r\n",
                               app_start_addr,
                               pageSize);

        /* round down the read size to a multiple of the page size
           that still fits inside the main buffer.
        */
        uint32_t readSize = (BUFFER_SIZE / pageSize) * pageSize;

        arm_uc_buffer_t buffer = {
            .size_max = readSize,
            .size     = 0,
            .ptr      = buffer_array
        };

        result = true;
        uint32_t offset = 0;

        /* write firmware */
        while ((offset < details->size) &&
                (result == true)) {
            /* clear most recent UCP event */
            event_callback = CLEAR_EVENT;

            /* set the number of bytes expected */
            buffer.size = (details->size - offset) > buffer.size_max ?
                          buffer.size_max : (details->size - offset);

            /* fill buffer using UCP */
            arm_uc_error_t ucp_status = MBED_CLOUD_CLIENT_UPDATE_STORAGE.Read(index, offset, &buffer);

            /* wait for event if the call is accepted */
            if (ucp_status.error == ERR_NONE) {
                while (event_callback == CLEAR_EVENT) {
                    __WFI();
                }
            }

            /* check status and actual read size */
            if ((event_callback == ARM_UC_PAAL_EVENT_READ_DONE) &&
                    (buffer.size > 0)) {
                /* the last page, in the last buffer might not be completely
                   filled, round up the program size to include the last page
                */
                uint32_t programSize = (buffer.size + pageSize - 1)
                                       / pageSize * pageSize;

                int retval = arm_uc_flashiap_program(buffer.ptr,
                                                     app_start_addr + offset,
                                                     programSize);

                result = (retval == ARM_UC_FLASHIAP_SUCCESS);

#if defined(SHOW_PROGRESS_BAR) && SHOW_PROGRESS_BAR == 1
                printProgress(offset, details->size);
#endif

                offset += programSize;
            } else {
                boot_debug("[DBG ] ARM_UCP_Read returned 0 bytes\r\n");

                /* set error and break out of loop */
                result = false;
                break;
            }
        }
    }

    return result;
}

/*
 * Copy loop to update the application
 */
bool copyStoredApplication(uint32_t index,
                           arm_uc_firmware_details_t *details)
{
    bool result = false;

    /*************************************************************************/
    /* Step 1. Erase active application                                      */
    /*************************************************************************/

    boot_debug("[DBG ] Erase active application\r\n");
    result = eraseActiveFirmware(details->size);

    /*************************************************************************/
    /* Step 2. Write header                                                  */
    /*************************************************************************/

    if (result) {
        boot_debug("[DBG ] Write header\r\n");
        result = writeActiveFirmwareHeader(details);
    }

    /*************************************************************************/
    /* Step 3. Copy application                                              */
    /*************************************************************************/

    if (result) {
        boot_debug("[DBG ] Copy application\r\n");
        result = writeActiveFirmware(index, details);
    }

    /*************************************************************************/
    /* Step 4. Verify application                                            */
    /*************************************************************************/

    if (result) {
        boot_debug("[DBG ] Verify application\r\n");
        int recheck = checkActiveApplication(details);

        result = (recheck == RESULT_SUCCESS);
    }

    return result;
}
