//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2016 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#if defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1)
#include <mbed.h>
#include <greentea-client/test_env.h>
#include <arm_test_pcut_jig_api.h>

#include "bootloader_power_cut_test.h"

DigitalOut JigTrigger(D2,0);

Timeout JigTimeout;

void power_cut_test_setup()
{
    arm_test_pcut_init(&JigTimeout, &JigTrigger, NULL, NULL);

    greentea_send_kv("send_sync", 0);
    GREENTEA_SETUP(600, "bootloader_power_cut_test");

    arm_test_pcut_request_cutpoint();

    printf("Ready!\n");
}

void power_cut_test_success()
{
    GREENTEA_TESTSUITE_RESULT(true);
}

void power_cut_test_fail()
{
    GREENTEA_TESTSUITE_RESULT(false);
}

void power_cut_test_end()
{
    greentea_send_kv("power_cut_test_end", 0);

    /* test end block forever */
    for (;;)
    {
        __WFI();
    }
}

void power_cut_test_assert_state(power_cut_test_state_t state)
{
    arm_test_pcut_assert_state((uint32_t) state);
}
#endif
