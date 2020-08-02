// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
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

#ifndef __FOTA_CURR_FW_H_
#define __FOTA_CURR_FW_H_

#include "fota/fota_base.h"
#include "fota_header_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return a pointer to application start.
 *
 * \return Pointer to application start.
 */
uint8_t *fota_curr_fw_get_app_start_addr(void);

/**
 * Return a pointer to header start.
 *
 * \return Pointer to header start.
 */
uint8_t *fota_curr_fw_get_app_header_addr(void);

#if defined(FOTA_CUSTOM_CURR_FW_STRUCTURE) && (FOTA_CUSTOM_CURR_FW_STRUCTURE)
/**
 * Read header of current firmware.
 *
 * \param[in] header_info Header info structure.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read_header(fota_header_info_t *header_info);
#else

// Default read header implementation
static inline int fota_curr_fw_read_header(fota_header_info_t *header_info)
{
    uint8_t *header_in_curr_fw = (uint8_t *)fota_curr_fw_get_app_header_addr();
    return fota_deserialize_header(header_in_curr_fw, fota_get_header_size(), header_info);
}
#endif

/**
 * Read from current firmware.
 *
 * \param[out] buf       Buffer to read into.
 * \param[in]  offset    Offset in firmware.
 * \param[in]  size      Size to read (bytes).
 * \param[out] num_read  Number of read bytes.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read(uint8_t *buf, uint32_t offset, uint32_t size, uint32_t *num_read);

/**
 * Read digest from current firmware.
 *
 * \param[out]  buf     Buffer to read into.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_get_digest(uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_CURR_FW_H_
