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

#ifndef __FOTA_STATUS_H_
#define __FOTA_STATUS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FOTA_STATUS_FW_UPDATE_OK                  = 18,  /**< Asset update successfully completed */

    FOTA_STATUS_MANIFEST_INVALID_URI          = -21, /**< FW payload URI in manifest is too long */
    FOTA_STATUS_MANIFEST_MALFORMED            = -22, /**< Failure to parse an update manifest */
    FOTA_STATUS_MANIFEST_SIGNATURE_INVALID    = -23, /**< Signature verification failed */
    FOTA_STATUS_DOWNLOAD_FRAGMENT_FAILED      = -24, /**< Connection lost during download */
    FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED  = -25, /**< Payload format specified by manifest is unsupported */
    FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED    = -26, /**< Payload authenticity check failed */
    FOTA_STATUS_MANIFEST_VERSION_REJECTED     = -27, /**< FW candidate version is rejected (is older or equals to installed one) */
    FOTA_STATUS_MANIFEST_SCHEMA_UNSUPPORTED   = -28, /**< Manifest schema version unsupported (incompatible manifest-tool version) */
    FOTA_STATUS_MANIFEST_CUSTOM_DATA_TOO_BIG  = -29, /**< Vendor data specified in a manifest is too big. */
    FOTA_STATUS_MANIFEST_WRONG_VENDOR_ID      = -30, /**< Manifest with wrong vendor id */
    FOTA_STATUS_MANIFEST_WRONG_CLASS_ID       = -31, /**< Manifest with wrong class id */
    FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH   = -32, /**< Installed FW digest differs from the one specified in manifest (precursor) */
    FOTA_STATUS_INSUFFICIENT_STORAGE          = -33, /**< Insufficient storage on a device for saving update candidate */
    FOTA_STATUS_OUT_OF_MEMORY                 = -34, /**< Not enough RAM */
    FOTA_STATUS_STORAGE_WRITE_FAILED          = -35, /**< Storage write error */
    FOTA_STATUS_STORAGE_READ_FAILED           = -36, /**< Storage read error */
    FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED      = -37, /**< Application rejected install authorization request */
    FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED     = -38, /**< Application rejected download authorization request */
    FOTA_STATUS_UNEXPECTED_COMPONENT          = -39, /**< Component name in manifest targets unknown component */
    FOTA_STATUS_MANIFEST_UNKNOWN_COMPONENT = FOTA_STATUS_UNEXPECTED_COMPONENT, // TODO: remove
    FOTA_STATUS_FW_INSTALLATION_FAILED        = -40, /**< Update failed at installation phase */
    FOTA_STATUS_INTERNAL_ERROR                = -41, /**< Non-specific internal error */
    FOTA_STATUS_INTERNAL_DELTA_ERROR          = -42, /**< Non-specific internal error - delta engine */
    FOTA_STATUS_INTERNAL_CRYPTO_ERROR         = -43, /**< Non-specific internal error - crypto engine */
    FOTA_STATUS_NOT_FOUND                     = -44, /**< Expected asset is not found in NVM */

    // internal transient errors - should not be reported to service
    FOTA_STATUS_SUCCESS                       = 0,   /**< all good */
    FOTA_STATUS_INVALID_ERR_CODE              = -1,  /**< Invalid error code, for internal purposes */
    FOTA_STATUS_FAIL_UPDATE_STATE             = -80, /**< Failed to deliver FOTA state */
    FOTA_STATUS_UPDATE_DEFERRED               = -81, /**< Application deferred the update */
    FOTA_STATUS_TRANSIENT_FAILURE             = -82, /**< transient failure during update **/
    FOTA_STATUS_FW_DELTA_REQUIRED_MORE_DATA   = -83, /**< Delta engine requires more data to proceed */
    FOTA_STATUS_FW_SIZE_MISMATCH              = -84, /**< FW fetching returned more data than expected - should not happen */
    FOTA_STATUS_RESOURCE_BUSY                 = -85, /**< Resource (typically storage) is busy */
    FOTA_STATUS_MULTICAST_UPDATE_ABORTED      = -86, /**< Received abort request from Multicast */
    FOTA_STATUS_MULTICAST_UPDATE_ACTIVATED    = -87, /**< Received abort request or new manifest from Multicast, when previous one was activated*/
    FOTA_STATUS_INVALID_ARGUMENT			  = -88	 /**< Invalid argument was received */
} fota_status_e;


#ifdef __cplusplus
}
#endif

#endif  // __FOTA_STATUS_H_
