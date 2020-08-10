// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#ifndef __FOTA_PLATFORM_H_
#define __FOTA_PLATFORM_H_

#include "fota/fota_base.h"
#include "fota/fota_status.h"
#include "fota/fota_block_device.h"
#include "fota/fota_candidate.h"

#ifdef __cplusplus
extern "C" {
#endif


#if defined(FOTA_CUSTOM_PLATFORM) && (FOTA_CUSTOM_PLATFORM)

// Hooks that need to be supplied by platform specific code

/**
 * Platform init hook, called at FOTA module initialization.
 *
 * \param[in] after_upgrade Indicates that hook was called after an upgrade.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_init_hook(bool after_upgrade);

/**
 * Platform start update hook, called when update is started.
 *
 * \param[in] comp_name Component name.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_start_update_hook(const char *comp_name);

/**
 * Platform finish update hook, called when update is finished.
 *
 * \param[in] comp_name Component name.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_finish_update_hook(const char *comp_name);

/**
 * Platform start update hook, called when update is aborted.
 *
 * \param[in] comp_name Component name.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_abort_update_hook(const char *comp_name);

#else

#ifdef __MBED__
// Default platform hooks
static inline int fota_platform_init_hook(bool after_upgrade)
{
    return FOTA_STATUS_SUCCESS;
}
#endif

static inline int fota_platform_start_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

static inline int fota_platform_finish_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

static inline int fota_platform_abort_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

#endif // !defined(FOTA_CUSTOM_PLATFORM) || (!FOTA_CUSTOM_PLATFORM)

#ifdef __cplusplus
}
#endif

#endif // __FOTA_PLATFORM_H_
