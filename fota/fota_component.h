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

#ifndef __FOTA_COMPONENT_H_
#define __FOTA_COMPONENT_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_component_defs.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_candidate.h"
#include "fota/fota_header_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file fota_component.h
 *  \brief Functions required for implementing the component update feature.
 */

/**
 * A callback function to read the current firmware.
 * Required only if delta update is supported for this component.
 *
 * \param[out] buf Buffer with data about the current firmware.
 * \param[in] offset Offset from which to read.
 * \param[in] size Output buffer size.
 * \param[in] num_read Actual size read.
 *
 * \return ::FOTA_STATUS_SUCCESS for a successful read operation.
 */
typedef int (*fota_component_curr_fw_read)(uint8_t *buf, size_t offset, size_t size, size_t *num_read);

/**
 * A callback function to get the current firmware digest.
 * Required only if delta update is supported for this component.
 *
 * \param[out] buf A buffer with the current firmware digest.
 *                 Make sure the size of the buffer is sufficient to hold the digest.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
typedef int (*fota_component_curr_fw_get_digest)(uint8_t *buf);

/**
 * A callback function to verify component installation success.
 * Executed after component installation.
 *
 * \param[in] component_name Name of the installed component. The same name that was specified as an argument to ::fota_component_add().
 * \param[in] expected_header_info Header with expected values for installed components.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
typedef int (*fota_component_verify_install_handler_t)(const char *comp_name, const fota_header_info_t *expected_header_info);


/**
 * Component description information.
 *
 * @param install_alignment The preferred installer fragment size. Typically equal to the flash program size.
 * @param support_delta Specify whether the component supports differential (delta) update.
 * @param need_reboot Specify whether the component requires system reboot after the component installation has completed.
                               Only `true` parameter is currently supported.
 * @param candidate_iterate_cb A callback function the FOTA client calls for installing the candidate.
 *                             The FOTA client calls the callback iteratively with a firmware fragment buffer pointer as an argument.
 *                             Note: For Linux systems, this iterative callback is replaced by ::fota_app_on_install_candidate().
 * @param component_verify_install_cb A callback function to be executed after installation, verifying installation.
 * @param curr_fw_read Only required if ::support delta is set to true.
 *                     A helper function for reading the currently installed firmware of the component.
 *                     A callback to read the current firmware.
 * @param curr_fw_get_digest Only required if ::support delta is set to true.
 *                           A helper function for calculating the SHA256 digest of the currently installed firmware of the component.
 *                           A callback to get the current firmware digest.
 */
typedef struct {
    uint32_t install_alignment;
    bool support_delta;
    bool need_reboot;
#if !defined(TARGET_LIKE_LINUX)
    fota_candidate_iterate_handler_t candidate_iterate_cb;
#endif
    fota_component_verify_install_handler_t component_verify_install_cb;
    fota_component_curr_fw_read curr_fw_read;
    fota_component_curr_fw_get_digest curr_fw_get_digest;
} fota_component_desc_info_t;

/**
 * Component registration.
 * Adds the component to the component database.
 * The function should be called from the ::fota_platform_init_hook() function.
 * The component description should reside in the stack to prevent unnecessary allocations and memory copies.
 *
 * \param[in] comp_desc Component description with required information.
 * \param[in] comp_name A string value representing the component name to add. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
 * \param[in] comp_semver A string value representing the [Semantic Version](https://semver.org/) of the component firmware installed at the factory.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_component_add(const fota_component_desc_info_t *comp_desc, const char *comp_name, const char *comp_semver);

/**
 * Convert internal FOTA library semantic version representation to a human-readable string.
 *
 * The version in the internal FOTA library representation passed to ::fota_app_on_download_authorization() and
 * candidate callback APIs.
 *
 * \param[in] version Internal version representation. Component description with required information.
 * \param[in] sem_ver
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_component_version_int_to_semver(fota_component_version_t version, char *sem_ver);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_COMPONENT_H_
