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

#if (defined(FIRMWARE_UPDATE_TEST) && (FIRMWARE_UPDATE_TEST == 1)) || \
    (defined(BOOTLOADER_POWER_CUT_TEST) && (BOOTLOADER_POWER_CUT_TEST == 1))

void copyAppToSDCard(uint32_t firmware_size);

void firmware_update_test_setup();

void firmware_update_test_validate();

void firmware_update_test_end();

#endif