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

#ifdef BOOTLOADER_POWER_CUT_TEST
#ifndef __BOOTLOADER_POWER_CUT_TEST_H__
#define __BOOTLOADER_POWER_CUT_TEST_H__

typedef enum {
    POWER_CUT_TEST_STATE_START,
    POWER_CUT_TEST_STATE_ERASE,
    POWER_CUT_TEST_STATE_COPY_FIRMWARE,
    POWER_CUT_TEST_STATE_FIRMWARE_VALIDATION,
    POWER_CUT_TEST_STATE_END
} power_cut_test_state_t;

void power_cut_test_setup();
void power_cut_test_success();
void power_cut_test_fail();
void power_cut_test_end();
void power_cut_test_assert_state(power_cut_test_state_t state);

#endif /* __BOOTLOADER_POWER_CUT_TEST_H__ */
#endif /* BOOTLOADER_POWER_CUT_TEST */
