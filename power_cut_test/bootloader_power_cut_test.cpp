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
// -----------------------------------------------------------------------------

#if defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1)
#include <mbed.h>
#include <greentea-client/test_env.h>
#include <arm_test_pcut_jig_api.h>

#include "bootloader_power_cut_test.h"

DigitalOut JigTrigger(D2, 0);

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
    for (;;) {
        __WFI();
    }
}

void power_cut_test_assert_state(power_cut_test_state_t state)
{
    arm_test_pcut_assert_state((uint32_t) state);
}
#endif
