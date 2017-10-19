//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#if (defined(FIRMWARE_UPDATE_TEST) && (FIRMWARE_UPDATE_TEST == 1)) || \
    (defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1))
#include <greentea-client/test_env.h>
#include "update-client-paal/arm_uc_paal_update.h"
#include "bootloader_common.h"
#include "active_application.h"
#include "pal.h"
#include "mbed.h"
#include "mbedtls/sha256.h"

#if !defined(UINT32_MAX)
#define UINT32_MAX  ((uint32_t)-1)
#endif

void copyAppToSDCard(uint32_t firmware_size)
{
    tr_info("Copy active firmware to slot 0\r\n");

    arm_uc_firmware_details_t details = { 0 };

    tr_info("calculate firmware SHA256\r\n");
    const uint8_t* appStart =
        (const uint8_t*) (MBED_CONF_APP_FIRMWARE_METADATA_HEADER_ADDRESS +
                          MBED_CONF_APP_FIRMWARE_METADATA_HEADER_SIZE);
    mbedtls_sha256(appStart, firmware_size, details.hash, 0);

    details.version = UINT32_MAX - 1;
    details.size = firmware_size;

    tr_info("ARM_UCP_Prepare\r\n");

    /* clear most recent event */
    event_callback = CLEAR_EVENT;

    arm_uc_buffer_t temp_buffer = {
        .size_max = BUFFER_SIZE,
        .size     = 0,
        .ptr      = buffer_array
    };

    /* prepare UCP to receive new image */
    arm_uc_error_t ucp_status = ARM_UCP_Prepare(0, &details, &temp_buffer);

    /* wait for event if call was accepted */
    if (ucp_status.error == ERR_NONE)
    {
        while (event_callback == CLEAR_EVENT)
        {
            __WFI();
        }
    }
    else
    {
        tr_error("ARM_UCP_Prepare failed\r\n");
    }

    /*************************************************************************/

    tr_info("ARM_UCP_Write\r\n");

    arm_uc_buffer_t write_buffer = {
        .size_max = firmware_size,
        .size     = firmware_size,
        .ptr      = (uint8_t*) appStart
    };

    /* clear most recent event */
    event_callback = CLEAR_EVENT;

    /* prepare UCP to receive new image */
    ucp_status = ARM_UCP_Write(0, 0, &write_buffer);

    /* wait for event if call was accepted */
    if (ucp_status.error == ERR_NONE)
    {
        while (event_callback == CLEAR_EVENT)
        {
            __WFI();
        }
    }
    else
    {
        tr_error("ARM_UCP_Write failed\r\n");
    }

    /*************************************************************************/

    tr_info("ARM_UCP_Finalize\r\n");

    /* clear most recent event */
    event_callback = CLEAR_EVENT;

    /* prepare UCP to receive new image */
    ucp_status = ARM_UCP_Finalize(0);

    /* wait for event if call was accepted */
    if (ucp_status.error == ERR_NONE)
    {
        while (event_callback == CLEAR_EVENT)
        {
            __WFI();
        }
    }
    else
    {
        tr_error("ARM_UCP_Finalize failed\r\n");
    }
}

static volatile uint8_t firmware_update_test_valid_flag = 0;

void firmware_update_test_setup()
{
    firmware_update_test_valid_flag = 0;
    GREENTEA_SETUP(60, "default_auto");
}

void firmware_update_test_validate()
{
    firmware_update_test_valid_flag = 1;
}

void firmware_update_test_end()
{
    if (firmware_update_test_valid_flag)
    {
        GREENTEA_TESTSUITE_RESULT(true);
    }
    else
    {
        GREENTEA_TESTSUITE_RESULT(false);
    }

    /* test end block forever */
    for (;;)
    {
        __WFI();
    }
}

#endif
