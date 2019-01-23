// ----------------------------------------------------------------------------
// Copyright 2017-2018 ARM Ltd.
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
#if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) && (ARM_UC_FEATURE_PAL_BLOCKDEVICE == 1)
#if defined(TARGET_LIKE_MBED)

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_platform.h"
#include "mbed.h"

BlockDevice *arm_uc_blockdevice_ext = BlockDevice::get_default_instance();

int32_t arm_uc_blockdevice_init(void)
{
    return arm_uc_blockdevice_ext->init();
}

uint32_t arm_uc_blockdevice_get_program_size(void)
{
    return arm_uc_blockdevice_ext->get_program_size();
}

uint32_t arm_uc_blockdevice_get_erase_size(void)
{
    return arm_uc_blockdevice_ext->get_erase_size();
}

int32_t arm_uc_blockdevice_erase(uint64_t address, uint64_t size)
{
    return arm_uc_blockdevice_ext->erase(address, size);
}

int32_t arm_uc_blockdevice_program(const uint8_t *buffer,
                                   uint64_t address,
                                   uint32_t size)
{
    return arm_uc_blockdevice_ext->program(buffer, address, size);
}

int32_t arm_uc_blockdevice_read(uint8_t *buffer,
                                uint64_t address,
                                uint32_t size)
{
    return arm_uc_blockdevice_ext->read(buffer, address, size);
}

#endif /* #if defined(TARGET_LIKE_MBED) */
#endif /* defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) */
