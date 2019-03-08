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

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_FLASHIAP) && (ARM_UC_FEATURE_PAL_FLASHIAP == 1)

#include "update-client-paal/arm_uc_paal_update_api.h"

#include "update-client-pal-flashiap/arm_uc_pal_flashiap_implementation.h"

ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UC_PAL_FlashIAP_GetCapabilities(void)
{
    ARM_UC_PAAL_UPDATE_CAPABILITIES result = {
        .installer_arm_hash = 0,
        .installer_oem_hash = 0,
        .installer_layout   = 0,
        .firmware_hash      = 1,
        .firmware_hmac      = 0,
        .firmware_campaign  = 0,
        .firmware_version   = 1,
        .firmware_size      = 1
    };

    return result;
}

const ARM_UC_PAAL_UPDATE ARM_UCP_FLASHIAP = {
    .Initialize                 = ARM_UC_PAL_FlashIAP_Initialize,
    .GetCapabilities            = ARM_UC_PAL_FlashIAP_GetCapabilities,
    .GetMaxID                   = ARM_UC_PAL_FlashIAP_GetMaxID,
    .Prepare                    = ARM_UC_PAL_FlashIAP_Prepare,
    .Write                      = ARM_UC_PAL_FlashIAP_Write,
    .Finalize                   = ARM_UC_PAL_FlashIAP_Finalize,
    .Read                       = ARM_UC_PAL_FlashIAP_Read,
    .Activate                   = ARM_UC_PAL_FlashIAP_Activate,
    .GetActiveFirmwareDetails   = ARM_UC_PAL_FlashIAP_GetActiveDetails,
    .GetFirmwareDetails         = ARM_UC_PAL_FlashIAP_GetFirmwareDetails,
    .GetInstallerDetails        = ARM_UC_PAL_FlashIAP_GetInstallerDetails
};

#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
