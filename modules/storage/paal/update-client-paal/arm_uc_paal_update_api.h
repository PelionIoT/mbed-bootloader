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

#ifndef ARM_UC_PAAL_UPDATE_API_H
#define ARM_UC_PAAL_UPDATE_API_H

#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <string.h>
#include <stdint.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1

#include "mbed-trace/mbed_trace.h"
#ifndef TRACE_GROUP
#define TRACE_GROUP  "UCPI"
#endif

#define ARM_UC_TRACE_DEBUG_PRINTF(module, fmt, ...) tr_debug("[%-4s] %s:%d: " fmt, module, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define ARM_UC_TRACE_ERROR_PRINTF(module, fmt, ...) tr_error("[%-4s] %s:%d: " fmt, module, __FILENAME__, __LINE__, ##__VA_ARGS__)

#else // if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1

#include <stdio.h>

#define ARM_UC_TRACE_DEBUG_PRINTF(module, fmt, ...) printf("[TRACE][%-4s] %s:%d: " fmt "\r\n", module, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define ARM_UC_TRACE_ERROR_PRINTF(module, fmt, ...) printf("[ERROR][%-4s] %s:%d: " fmt "\r\n", module, __FILENAME__, __LINE__, ##__VA_ARGS__)

#endif // if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1

#if ARM_UC_PAAL_TRACE_ENABLE
#define UC_PAAL_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("PAAL", fmt, ##__VA_ARGS__)
#define UC_PAAL_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("PAAL", fmt, ##__VA_ARGS__)
#else
#define UC_PAAL_TRACE(fmt, ...)
#define UC_PAAL_ERR_MSG(fmt, ...)
#endif // if ARM_UC_PAAL_TRACE_ENABLE

/**
 * @brief Prototype for event handler.
 */
typedef void (*ARM_UC_PAAL_UPDATE_SignalEvent_t)(uint32_t event);

/**
 * @brief Asynchronous events.
 */
enum {
    ARM_UC_PAAL_EVENT_INITIALIZE_DONE,
    ARM_UC_PAAL_EVENT_PREPARE_DONE,
    ARM_UC_PAAL_EVENT_WRITE_DONE,
    ARM_UC_PAAL_EVENT_FINALIZE_DONE,
    ARM_UC_PAAL_EVENT_READ_DONE,
    ARM_UC_PAAL_EVENT_ACTIVATE_DONE,
    ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE,
    ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE,
    ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE,
    ARM_UC_PAAL_EVENT_INITIALIZE_ERROR,
    ARM_UC_PAAL_EVENT_PREPARE_ERROR,
    ARM_UC_PAAL_EVENT_FIRMWARE_TOO_LARGE_ERROR,
    ARM_UC_PAAL_EVENT_WRITE_ERROR,
    ARM_UC_PAAL_EVENT_FINALIZE_ERROR,
    ARM_UC_PAAL_EVENT_READ_ERROR,
    ARM_UC_PAAL_EVENT_ACTIVATE_ERROR,
    ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR,
    ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_ERROR,
    ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_ERROR,
};

/**
 * @brief Bitmap with supported header features.
 * @details The PAAL Update implementation indicates what features are
 *          supported. This can be used after a call to one of the GetDetails
 *          to see which fields have valid values and what fields should be set
 *          in the call to Prepare.
 */
typedef struct _ARM_UC_PAAL_UPDATE_CAPABILITIES {
    uint32_t installer_arm_hash: 1;
    uint32_t installer_oem_hash: 1;
    uint32_t installer_layout: 1;
    uint32_t firmware_hash: 1;
    uint32_t firmware_hmac: 1;
    uint32_t firmware_campaign: 1;
    uint32_t firmware_version: 1;
    uint32_t firmware_size: 1;
    uint32_t reserved: 24;
} ARM_UC_PAAL_UPDATE_CAPABILITIES;

/**
 * @brief Structure definition holding API function pointers.
 */
typedef struct _ARM_UC_PAAL_UPDATE {

    /**
     * @brief Initialize the underlying storage and set the callback handler.
     *
     * @param callback Function pointer to event handler.
     * @return Returns ERR_NONE on accept, and signals the event handler with
     *         either DONE or ERROR when complete.
     *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
     */
    arm_uc_error_t (*Initialize)(ARM_UC_PAAL_UPDATE_SignalEvent_t callback);

    /**
     * @brief Get a bitmap indicating supported features.
     * @details The bitmap is used in conjunction with the firmware and
     *          installer details struct to indicate what fields are supported
     *          and which values are valid.
     *
     * @return Capability bitmap.
     */
    ARM_UC_PAAL_UPDATE_CAPABILITIES(*GetCapabilities)(void);

    /**
     * @brief Get maximum number of supported storage locations.
     *
     * @return Number of storage locations.
     */
    uint32_t (*GetMaxID)(void);

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
    arm_uc_error_t (*Prepare)(uint32_t location,
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
    arm_uc_error_t (*Write)(uint32_t location,
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
    arm_uc_error_t (*Finalize)(uint32_t location);

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
    arm_uc_error_t (*Read)(uint32_t location,
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
    arm_uc_error_t (*Activate)(uint32_t location);

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
    arm_uc_error_t (*GetActiveFirmwareDetails)(arm_uc_firmware_details_t *details);

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
    arm_uc_error_t (*GetFirmwareDetails)(uint32_t location,
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
    arm_uc_error_t (*GetInstallerDetails)(arm_uc_installer_details_t *details);

} ARM_UC_PAAL_UPDATE;

#endif /* ARM_UC_PAAL_UPDATE_API_H */
