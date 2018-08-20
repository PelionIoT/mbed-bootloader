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

#include "update-client-paal/arm_uc_paal_update_api.h"

#include <stdint.h>

bool activeStorageInit(void);
void activeStorageDeinit(void);

/**
 * Read the metadata header of the active image from internal flash
 * @param  headerP
 *             Caller-allocated header structure.
 * @return true if the read succeeds.
 */
bool readActiveFirmwareHeader(arm_uc_firmware_details_t *details);

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
int checkActiveApplication(arm_uc_firmware_details_t *details);

bool copyStoredApplication(uint32_t index, arm_uc_firmware_details_t *details);
