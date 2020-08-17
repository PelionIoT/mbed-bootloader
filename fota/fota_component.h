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

#ifndef __FOTA_COMPONENT_H_
#define __FOTA_COMPONENT_H_

#include "fota/fota_base.h"
#include "fota/fota_component_defs.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_candidate.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback to read current firmware, required only if delta supported.
 *
 * \param[out] buf buffer with curr fw data.
 * \param[in] offset offset where to read from.
 * \param[in] size output buffer size.
 * \param[in] num_read actual size read.
 * \return FOTA_STATUS_SUCCESS for succesfull read.
 */
typedef int (*fota_component_curr_fw_read)(uint8_t *buf, uint32_t offset, uint32_t size, uint32_t *num_read);

/**
 * Callback to get current firmware digest, required only if delta supported.
 *
 * \param[out] buf buffer with current firmware digest, should be big enought to hold it.
 * \return FOTA_STATUS_SUCCESS on success.
 */
typedef int (*fota_component_curr_fw_get_digest)(uint8_t *buf);

/**
 * Callback called handle post install.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
typedef int (*fota_component_post_install_handler_t)(const char *new_sem_ver);

/**
 * Component description info
 *
 * install_alignment If set to non-zero, fragment sizes returned to the user will be aligned to this value.
 * candidate_iterate_cb callback to candidate iterate firmware function.
 * support_delta if delta update supported for component.
 * component_post_install_cb callback to for post install component check.
 * curr_fw_read callback to read current firmware. Required only if delta is supported for current component, NULL otherwise.
 * curr_fw_get_digest callback to get current firmware digest. Required only if delta is supported for current component, NULL otherwise.
 * need_reboot if reboot required after installation.
 */
typedef struct {
    uint32_t install_alignment;
    fota_candidate_iterate_handler_t candidate_iterate_cb;
    fota_component_post_install_handler_t component_post_install_cb;
    bool support_delta;
    fota_component_curr_fw_read curr_fw_read;
    fota_component_curr_fw_get_digest curr_fw_get_digest;
    bool need_reboot;
} fota_component_desc_info_t;

/**
 * Component registration, adding to component database.
 * Component description should reside in text section to prevent unnecessary allocations and memory copies.
 *
 * \param[in] comp_desc component description info with required information.
 * \param[in] comp_name component name to add.
 * \param[in] comp_semver component semver.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_component_add(const fota_component_desc_info_t *comp_desc, const char *comp_name, const char *comp_semver);

/**
 * Convert internal FOTA library semantic version representation to human readable string.
 * 
 * The version in internal FOTA library representation passed to fota_app_on_download_authorization() and 
 * candidate callback APIs.
 */
int fota_component_version_int_to_semver(fota_component_version_t version, char *sem_ver);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_COMPONENT_H_
