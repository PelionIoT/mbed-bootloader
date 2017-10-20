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

#include "update-client-common/arm_uc_utilities.h"
#include "update-client-common/arm_uc_metadata_header_v2.h"
#include "update-client-paal/arm_uc_paal_update.h"
#include "mbed.h"

#include <inttypes.h>

static FlashIAP flash;

bool activeStorageInit(void)
{
    int rc = flash.init();

    return (rc == 0);
}

void activeStorageDeinit(void)
{
    flash.deinit();
}

/**
 * Read the metadata header of the active image from internal flash
 * @param  headerP
 *             Caller-allocated header structure.
 * @return true if the read succeeds.
 */
bool readActiveFirmwareHeader(arm_uc_firmware_details_t* details)
{
    tr_debug("readActiveFirmwareHeader");

    bool result = false;

    if (details)
    {
        /* clear most recent UCP event */
        event_callback = CLEAR_EVENT;

        /* get active firmware details using UCP */
        arm_uc_error_t status = ARM_UCP_GetActiveFirmwareDetails(details);

        /* if the call was accepted,
           the event will indicate if the call succeeded
        */
        if (status.error == ERR_NONE)
        {
            /* wait until the event has been set */
            while (event_callback == CLEAR_EVENT)
            {
                __WFI();
            }

            /* mark the firmware details as valid if so indicated by the event */
            if (event_callback == ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE)
            {
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
int checkActiveApplication(arm_uc_firmware_details_t* details)
{
    tr_debug("checkActiveApplication");

    int result = RESULT_ERROR;

    if (details)
    {
        /* Read header and verify that it is valid */
        bool headerValid = readActiveFirmwareHeader(details);

        /* calculate hash if header is valid and slot is not empty */
        if ((headerValid) && (details->size > 0))
        {
            uint32_t appStart = MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS +
                                MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE;

            tr_debug("header start: 0x%08" PRIX32,
                     (uint32_t) MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS);
            tr_debug("header size: %" PRIu32,
                     (uint32_t) MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE);
            tr_debug("app start: 0x%08" PRIX32, appStart);
            tr_debug("app size: %" PRIu64, details->size);

            /* initialize hashing facility */
            palMDHandle_t md = { 0 };
            pal_mdInit(&md, PAL_SHA256);

            uint8_t SHA[PAL_SHA256_SIZE] = { 0 };
            uint32_t remaining = details->size;
            int32_t status = 0;

            /* read full image */
            while ((remaining > 0) && (status == 0))
            {
                /* read full buffer or what is remaining */
                uint32_t readSize = (remaining > BUFFER_SIZE) ?
                                    BUFFER_SIZE : remaining;

                /* read buffer using FlashIAP API for portability */
                status = flash.read(buffer_array,
                                    appStart + (details->size - remaining),
                                    readSize);

                /* update hash */
                pal_mdUpdate(md, buffer_array, readSize);

                /* update remaining bytes */
                remaining -= readSize;

#if defined(SHOW_PROGRESS_BAR) && SHOW_PROGRESS_BAR == 1
                printProgress(details->size - remaining,
                              details->size);
#endif
            }

            /* finalize hash */
            pal_mdFinal(md, SHA);
            pal_mdFree(&md);

            /* compare calculated hash with hash from header */
            int diff = memcmp(details->hash, SHA, PAL_SHA256_SIZE);

            if (diff == 0)
            {
                result = RESULT_SUCCESS;
            }
            else
            {
                printSHA256(details->hash);
                printSHA256(SHA);
            }
        }
        else if ((headerValid) && (details->size == 0))
        {
            /* header is valid but application size is 0 */
            result = RESULT_EMPTY;
        }
    }

    return result;
}

/**
 * Wipe the ACTIVE firmware region in the flash
 */
bool eraseActiveFirmware(uint32_t firmwareSize)
{
    tr_debug("eraseActiveFirmware");

    /* get sector size of where the new firmware would end */
    uint32_t lastSectorSize =
        flash.get_sector_size(MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS +
                              MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE +
                              firmwareSize);

    /* full size of header and application */
    uint32_t sizeRoundedUp = MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE +
                             firmwareSize;

    /* full size rounded up to erase sector boundary */
    sizeRoundedUp = ((sizeRoundedUp + lastSectorSize - 1) / lastSectorSize)
                    * lastSectorSize;

    tr_debug("Erasing from 0x%08" PRIX32 " to 0x%08" PRIX32,
             (uint32_t) MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS,
             (uint32_t) MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS + sizeRoundedUp);

    /* erase flash to make place for new application */
    int result = flash.erase(MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS,
                             sizeRoundedUp);

    return (result == 0);
}

bool writeActiveFirmwareHeader(arm_uc_firmware_details_t* details)
{
    tr_debug("writeActiveFirmwareHeader");

    bool result = false;

    if (details)
    {
        /* round up program size to nearest page size */
        const uint32_t pageSize = flash.get_page_size();
        const uint32_t programSize = (ARM_UC_INTERNAL_HEADER_SIZE_V2 + pageSize - 1)
                                     / pageSize * pageSize;

        ASSERT((programSize <= BUFFER_SIZE),
               "Header program size %" PRIu32 " bigger than buffer %d\r\n",
               programSize, BUFFER_SIZE);

        ASSERT((programSize <= MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE),
               "Header program size %" PRIu32 " bigger than expected header %d\r\n",
               programSize, MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE);

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
            (output_buffer.size == ARM_UC_INTERNAL_HEADER_SIZE_V2))
        {
            /* write header using FlashIAP API */
            int ret = flash.program(buffer_array,
                                    MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS,
                                    programSize);

            result = (ret == 0);
        }
    }

    return result;
}

bool writeActiveFirmware(uint32_t index, arm_uc_firmware_details_t* details)
{
    tr_debug("writeActiveFirmware");

    bool result = false;

    if (details)
    {
        const uint32_t pageSize = flash.get_page_size();

        /* we require app_start_addr fall on a page size boundary */
        uint32_t app_start_addr = MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS
                                + MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE;

        ASSERT((app_start_addr % pageSize) == 0,
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

        int retval = 0;
        uint32_t offset = 0;

        /* write firmware */
        while ((offset < details->size) &&
               (retval == 0))
        {
            /* clear most recent UCP event */
            event_callback = CLEAR_EVENT;

            /* fill buffer using UCP */
            arm_uc_error_t ucp_status = ARM_UCP_Read(index, offset, &buffer);

            /* wait for event if the call is accepted */
            if (ucp_status.error == ERR_NONE)
            {
                while (event_callback == CLEAR_EVENT)
                {
                    __WFI();
                }
            }

            /* check status and actual read size */
            if ((event_callback == ARM_UC_PAAL_EVENT_READ_DONE) &&
                (buffer.size > 0))
            {
                /* the last page, in the last buffer might not be completely
                   filled, round up the program size to include the last page
                */
                uint32_t programOffset = 0;
                uint32_t programSize = (buffer.size + pageSize - 1)
                                       / pageSize * pageSize;

                /* write one page at a time */
                while ((programOffset < programSize) &&
                       (retval == 0))
                {
                    retval = flash.program(&(buffer.ptr[programOffset]),
                                           app_start_addr + offset + programOffset,
                                           pageSize);

                    programOffset += pageSize;

#if defined(SHOW_PROGRESS_BAR) && SHOW_PROGRESS_BAR == 1
                    printProgress(offset + programOffset, details->size);
#endif
                }

                tr_debug("\r\n%" PRIu32 "/%" PRIu32 " writing %" PRIu32 " bytes to 0x%08" PRIX32,
                         offset, (uint32_t) details->size, programSize, app_start_addr + offset);

                offset += programSize;
            }
            else
            {
                tr_error("ARM_UCP_Read returned 0 bytes");

                /* set error and break out of loop */
                retval = -1;
                break;
            }
        }

        result = (retval == 0);
    }

    return result;
}

/*
 * Copy loop to update the application
 */
bool copyStoredApplication(uint32_t index,
                           arm_uc_firmware_details_t* details)
{
    tr_debug("copyStoredApplication");

    bool result = false;

    /*************************************************************************/
    /* Step 1. Erase active application                                      */
    /*************************************************************************/

    result = eraseActiveFirmware(details->size);

    /*************************************************************************/
    /* Step 2. Write header                                                  */
    /*************************************************************************/

    if (result)
    {
        result = writeActiveFirmwareHeader(details);
    }

    /*************************************************************************/
    /* Step 3. Copy application                                              */
    /*************************************************************************/

    if (result)
    {
        result = writeActiveFirmware(index, details);
    }

    /*************************************************************************/
    /* Step 4. Verify application                                            */
    /*************************************************************************/

    if (result)
    {
        tr_info("Verify new active firmware:");

        int recheck = checkActiveApplication(details);

        result = (recheck == RESULT_SUCCESS);
    }

    return result;
}
