//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2016-2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>

#include "mbed.h"
#include "FATFileSystem.h"

#include "update-client-pal-filesystem/arm_uc_pal_filesystem.h"
#include "update-client-paal/arm_uc_paal_update.h"
#include "update-client-common/arm_uc_types.h"
#include "SDBlockDevice.h"
#include "pal.h"

#include "mbed_bootloader_info.h"
#include "bootloader_platform.h"
#include "active_application.h"
#include "bootloader_common.h"
#include "mbed_application.h"
#include "upgrade.h"

#if defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1)
#include "bootloader_power_cut_test.h"
#include "firmware_update_test.h"
#endif

#if defined(FIRMWARE_UPDATE_TEST) && (FIRMWARE_UPDATE_TEST == 1)
#include "firmware_update_test.h"
#endif

const arm_uc_installer_details_t bootloader = {
    .arm_hash = BOOTLOADER_ARM_SOURCE_HASH,
    .oem_hash = BOOTLOADER_OEM_SOURCE_HASH,
    .layout   = BOOTLOADER_STORAGE_LAYOUT
};

/* initialise sd card and filesystem */
#if defined(MBED_CONF_APP_SPI_MOSI) && defined(MBED_CONF_APP_SPI_MISO) && \
    defined(MBED_CONF_APP_SPI_CLK)  && defined(MBED_CONF_APP_SPI_CS)
SDBlockDevice sd(MBED_CONF_APP_SPI_MOSI, MBED_CONF_APP_SPI_MISO,
                 MBED_CONF_APP_SPI_CLK,  MBED_CONF_APP_SPI_CS);
#else
SDBlockDevice sd(MBED_CONF_SD_SPI_MOSI, MBED_CONF_SD_SPI_MISO,
                 MBED_CONF_SD_SPI_CLK,  MBED_CONF_SD_SPI_CS);
#endif
FATFileSystem fs("sd", &sd);

int main(void)
{
    /* Use malloc to allocate uint64_t version number on the heap */
    heapVersion = (uint64_t*) malloc(sizeof(uint64_t));
    bootCounter = (uint8_t*) malloc(1);

    /* Set PAAL Update implementation before initializing Firmware Manager */
    ARM_UCP_SetPAALUpdate(&ARM_UCP_FILESYSTEM);

    /* Initialize PAL */
    arm_uc_error_t ucp_result = ARM_UCP_Initialize(arm_ucp_event_handler);

    /* If a reboot message was left from last boot, print it here */
    if (existsErrorMessageLeadingToReboot())
    {
        tr_info("error message leading to reboot: %s",
                errorMessageLeadingToReboot());
    }

#if defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1)
    power_cut_test_setup();
    const uint32_t firmware_size = 1000;
    copyAppToSDCard(firmware_size);
    power_cut_test_assert_state(POWER_CUT_TEST_STATE_START);
#elif defined(FIRMWARE_UPDATE_TEST) && (FIRMWARE_UPDATE_TEST == 1)
    const uint32_t firmware_size = 10000;
    copyAppToSDCard(firmware_size);
    firmware_update_test_setup();
#endif

    /*************************************************************************/
    /* Print bootloader information                                          */
    /*************************************************************************/

    tr_info("mbed Bootloader");

    uint8_t arm_size[] = BOOTLOADER_ARM_SOURCE_HASH;

    tr_trace("[BOOT] ARM: ");
    for (uint32_t index = 0; index < sizeof(arm_size); index++)
    {
        tr_trace("%02" PRIX8, bootloader.arm_hash[index]);
    }
    tr_trace("\r\n");

    uint8_t oem_size[] = BOOTLOADER_OEM_SOURCE_HASH;

    tr_trace("[BOOT] OEM: ");
    for (uint32_t index = 0; index < sizeof(oem_size); index++)
    {
        tr_trace("%02" PRIX8, bootloader.oem_hash[index]);
    }
    tr_trace("\r\n");

    tr_info("Layout: %" PRIu32 " %" PRIX32,
            bootloader.layout,
            (uint32_t) &bootloader);

    /*************************************************************************/
    /* Update                                                                */
    /*************************************************************************/

    /* Default to booting application */
    bool canForward = true;

    /* check UCP initialization result */
    if (ucp_result.error == ERR_NONE)
    {
        /* Initialize internal flash */
        bool storageResult = activeStorageInit();

        if (storageResult)
        {
            /* Try to update firmware from journal */
            canForward = upgradeApplicationFromStorage();

            /* deinit storage driver */
            activeStorageDeinit();
        }
    }

    /* forward control to ACTIVE application if it is deemed sane */
    if (canForward)
    {
#if defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1)
        power_cut_test_assert_state(POWER_CUT_TEST_STATE_END);
        wait(5);
        power_cut_test_end(); // Notify test end, host test will determine actual result
#elif defined(FIRMWARE_UPDATE_TEST) && (FIRMWARE_UPDATE_TEST == 1)
        firmware_update_test_end();
#endif
        uint32_t app_start_addr = MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS +
                                  MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE;
        uint32_t app_stack_ptr = *((uint32_t*)(app_start_addr + 0));
        uint32_t app_jump_addr = *((uint32_t*)(app_start_addr + 4));

        tr_info("Application's start address: 0x%" PRIX32, app_start_addr);
        tr_info("Application's jump address: 0x%" PRIX32, app_jump_addr);
        tr_info("Application's stack address: 0x%" PRIX32, app_stack_ptr);
        tr_info("Forwarding to application...\r\n");

        mbed_start_application(app_start_addr);
    }

    /* Reset bootCounter; this allows a user to reapply a new bootloader
       without having to power cycle the device.
    */
    if (bootCounter)
    {
        *bootCounter = 0;
    }

    ASSERT(false, "Failed to jump to application!");

    for (;;)
    {
        __WFI();
    }
}
