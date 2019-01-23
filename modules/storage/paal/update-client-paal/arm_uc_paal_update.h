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

#include "update-client-paal/arm_uc_paal_update_api.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set PAAL Update implementation.
 *
 * @param implementation Function pointer struct to implementation.
 * @return Returns ERR_NONE on accept and ERR_INVALID_PARAMETER otherwise.
 */
arm_uc_error_t ARM_UCP_SetPAALUpdate(const ARM_UC_PAAL_UPDATE *implementation);

/**
 * @brief Initialize the underlying storage and set the callback handler.
 *
 * @param callback Function pointer to event handler.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback);

/**
 * @brief Get a bitmap indicating supported features.
 * @details The bitmap is used in conjunction with the firmware and
 *          installer details struct to indicate what fields are supported
 *          and which values are valid.
 *
 * @return Capability bitmap.
 */
ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UCP_GetCapabilities(void);

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UCP_GetMaxID(void);

/**
 * @brief Prepare the storage layer for a new firmware image.
 * @details The storage location is set up to receive an image with
 *          the details passed in the details struct.
 *
 * @param location Storage location ID.
 * @param details Pointer to a struct with firmware details.
 * @param buffer Temporary buffer for formatting and storing metadata.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_Prepare(uint32_t location,
                               const arm_uc_firmware_details_t *details,
                               arm_uc_buffer_t *buffer);

/**
 * @brief Write a fragment to the indicated storage location.
 * @details The storage location must have been allocated using the Prepare
 *          call. The call is expected to write the entire fragment before
 *          signaling completion.
 *
 * @param location Storage location ID.
 * @param offset Offset in bytes to where the fragment should be written.
 * @param buffer Pointer to buffer struct with fragment.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_Write(uint32_t location,
                             uint32_t offset,
                             const arm_uc_buffer_t *buffer);

/**
 * @brief Close storage location for writing and flush pending data.
 *
 * @param location Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_Finalize(uint32_t location);

/**
 * @brief Read a fragment from the indicated storage location.
 * @details The function will read until the buffer is full or the end of
 *          the storage location has been reached. The actual amount of
 *          bytes read is set in the buffer struct.
 *
 * @param location Storage location ID.
 * @param offset Offset in bytes to read from.
 * @param buffer Pointer to buffer struct to store fragment. buffer->size
 *        contains the intended read size.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 *         buffer->size contains actual bytes read on return.
 */
arm_uc_error_t ARM_UCP_Read(uint32_t location,
                            uint32_t offset,
                            arm_uc_buffer_t *buffer);

/**
 * @brief Set the firmware image in the slot to be the new active image.
 * @details This call is responsible for initiating the process for
 *          applying a new/different image. Depending on the platform this
 *          could be:
 *           * An empty call, if the installer can deduce which slot to
 *             choose from based on the firmware details.
 *           * Setting a flag to indicate which slot to use next.
 *           * Decompressing/decrypting/installing the firmware image on
 *             top of another.
 *
 * @param location Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_Activate(uint32_t location);

/**
 * @brief Get firmware details for the actively running firmware.
 * @details This call populates the passed details struct with information
 *          about the currently active firmware image. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details);

/**
 * @brief Get firmware details for the firmware image in the slot passed.
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_GetFirmwareDetails(uint32_t location,
                                          arm_uc_firmware_details_t *details);

/**
 * @brief Get details for the component responsible for installation.
 * @details This call populates the passed details struct with information
 *          about the local installer. Only the fields marked as supported
 *          in the capabilities bitmap will have valid values. The
 *          installer could be the bootloader, a recovery image, or some
 *          other component responsible for applying the new firmware
 *          image.
 *
 * @param details Pointer to installer details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_GetInstallerDetails(arm_uc_installer_details_t *details);

#ifdef __cplusplus
}
#endif
