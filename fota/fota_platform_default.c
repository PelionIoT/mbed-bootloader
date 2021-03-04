// ----------------------------------------------------------------------------
// Copyright 2021 Pelion Ltd.
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
#include "fota_platform.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#if !defined(FOTA_CUSTOM_PLATFORM) || (!FOTA_CUSTOM_PLATFORM)

// Default platform hooks
int fota_platform_init_hook(bool after_upgrade)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_platform_start_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_platform_finish_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_platform_abort_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

#endif // !defined(FOTA_CUSTOM_PLATFORM) || (!FOTA_CUSTOM_PLATFORM)

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

