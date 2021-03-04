// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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
#include "fota/fota_config.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#include "fota/fota_block_device.h"

// Applies to the cases where we use the default block device - Charger bootloader and WIFI (both app & bootloader)
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_CUSTOM_BD)

#include "BlockDevice.h"

mbed::BlockDevice *fota_bd_get_custom_bd()
{
    return mbed::BlockDevice::get_default_instance();
}

#endif  // (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_CUSTOM_BD)
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
