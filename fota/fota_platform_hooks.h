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

#ifndef __FOTA_PLATFORM_H_
#define __FOTA_PLATFORM_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file fota_platform_hooks.h
 *  \brief Platform hooks that the platform can implement if the target requires more complex FOTA initialization and teardown steps.
 * By default, Pelion FOTA provides an empty implementation for these hooks.
 * An application developer can override these hooks by injecting the ::FOTA_CUSTOM_PLATFORM macro to the build and implementing all the callback functions listed below.
 */


/**
 * Platform init hook.
 * Called when the FOTA module is initialized.
 *
 * \param[in] after_upgrade Indicates that the hook is called after a successful upgrade of the installed image.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_init_hook(bool after_upgrade);

/**
 * Platform start update hook.
 * Called when the download of the update candidate begins.
 *
 * \param[in] comp_name Component name.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_start_update_hook(const char *comp_name);

/**
 * Platform finish update hook.
 * Called when the download of the update candidate ends.
 *
 * \param[in] comp_name Component name.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_finish_update_hook(const char *comp_name);

/**
 * Platform abort update hook.
 * Called when the download of the update candidate is aborted.
 *
 * \param[in] comp_name  Component name.
  * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_platform_abort_update_hook(const char *comp_name);


#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_PLATFORM_H_
