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

#include "update-client-paal/arm_uc_paal_update_api.h"

#include "pal.h"

#include <stdint.h>

bool activeStorageInit(void);
void activeStorageDeinit(void);

/**
 * Read the metadata header of the active image from internal flash
 * @param  headerP
 *             Caller-allocated header structure.
 * @return true if the read succeeds.
 */
bool readActiveFirmwareHeader(arm_uc_firmware_details_t* details);

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
int checkActiveApplication(arm_uc_firmware_details_t* details);

bool copyStoredApplication(uint32_t index, arm_uc_firmware_details_t* details);
