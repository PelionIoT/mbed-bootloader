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

#ifndef __FOTA_STATUS_H_
#define __FOTA_STATUS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FOTA_STATUS_SUCCESS                       =  0,   /**< all good */
    FOTA_STATUS_UPDATE_DEFERRED               = 17,   /**< user decided to defer the update **/
    FOTA_STATUS_FW_UPDATE_OK                  = 18,   /**< asset update successfully completed */

    FOTA_STATUS_FAIL_UPDATE_STATE             = -1,   /**< Failed to deliver FOTA state **/

    FOTA_STATUS_MANIFEST_INVALID_URI          = -3,   /**< manifest with wrong class uri */
    FOTA_STATUS_MANIFEST_MALFORMED            = -4,   /**< malformed manifest - parsing failed */
    FOTA_STATUS_MANIFEST_UNKNOWN_COMPONENT    = -5,   /**< component name in manifest belongs to an unknown component */
    FOTA_STATUS_CERT_NOT_FOUND                = -6,   /**< manifest rejected, certificate not found */
    FOTA_STATUS_MANIFEST_SIGNATURE_INVALID    = -7,   /**< manifest signature verification failed */
    FOTA_STATUS_INSUFFICIENT_STORAGE          = -9,   /**< insufficient storage for saving update candidate */
    FOTA_STATUS_OUT_OF_MEMORY                 = -10,  /**< not enough RAM */
    FOTA_STATUS_DOWNLOAD_FRAGMENT_FAILED      = -11,  /**< connection lost during download */
    FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH   = -12,  /**< precursor field in manifest payload does not match installed FW digest */
    FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED  = -13,  /**< payload format specified by manifest is unsupported */
    FOTA_STATUS_FW_INVALID_URI                = -14,  /**< invalid asset URI */
    FOTA_STATUS_FW_DOWNLOAD_TIMEOUT           = -15,  /**< timed out downloading asset */
    FOTA_STATUS_FW_UNSUPPORTED_DELTA_FORMAT   = -16,  /**< unsupported delta format */
    FOTA_STATUS_FW_UNSUPPORTED_ENCRYPT_FORMAT = -17,  /**< unsupported encryption format */
    FOTA_STATUS_FW_DELTA_REQUIRED_MORE_DATA   = -18,  /**< delta engine requred more data to proceed */



    FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED    = -102, /**< payload digest does not match to the one specified by manifest */
    FOTA_STATUS_NON_SPECIFIC_SYSTEM_ERROR     = -103, /**< update error, nonspecific system error */

    FOTA_STATUS_INVALID_CERTIFICATE           = -209, /**< manifest rejected, invalid certificate */
    FOTA_STATUS_MANIFEST_ALREADY_IN_PROCESS   = -212, /**< manifest rejected, device already processing manifest */
    FOTA_STATUS_MANIFEST_VERSION_REJECTED     = -213, /**< manifest payload version is older or equals to installed one */
    FOTA_STATUS_MANIFEST_SCHEMA_UNSUPPORTED   = -214, /**< manifest schema version unsupported */
    FOTA_STATUS_MANIFEST_WRONG_VENDOR_ID      = -215, /**< manifest with wrong vendor id */
    FOTA_STATUS_MANIFEST_WRONG_CLASS_ID       = -216, /**< manifest with wrong class id */
    FOTA_STATUS_MANIFEST_INVALID_SIZE         = -217, /**< malformed manifest - invalid size */
    FOTA_STATUS_MANIFEST_WRITE_ERROR          = -227, /**< manifest processing error, write error */
    FOTA_STATUS_MANIFEST_SEMVER_ERROR         = -228,  /**< error parsing semantic version */

    FOTA_STATUS_SOURCE_STATE_UPDATE_ERROR     = -310, /**< resource fetching, user-defined error 2 **/
    FOTA_STATUS_RESOURCE_NOT_AVAILABLE        = -311, /**< resource fetching, user-defined error 3 **/
    FOTA_STATUS_UNEXPECTED_COMPONENT          = -312, /**< resource fetching, user-defined error 5 **/
    FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED     = -313, /**< application rejected download authorization request */
    FOTA_STATUS_FW_INSTALLATION_FAILED        = -314, /**< update failed at installation phase */

    FOTA_STATUS_FW_SIZE_MISMATCH              = -400, /**< payload processing, nonspecific error */
    FOTA_STATUS_STORAGE_READ_FAILED           = -401, /**< payload processing, user-defined error 1 **/
    FOTA_STATUS_INVALID_DATA                  = -402, /**< payload processing, user-defined error 2 **/
    FOTA_STATUS_INTERNAL_DELTA_ERROR          = -403, /**< payload processing, user-defined error 3 **/
    FOTA_STATUS_INTERNAL_CRYPTO_ERROR         = -404, /**< payload processing, user-defined error 4 **/
    FOTA_STATUS_NOT_ALLOWED                   = -405, /**< payload processing, user-defined error 5 **/

    FOTA_STATUS_STORAGE_WRITE_FAILED          = -503, /**< payload writing error, write error */
    FOTA_STATUS_NOT_FOUND                     = -506, /**< payload writing error, user-defined error 1 **/
    FOTA_STATUS_NOT_INITIALIZED               = -507, /**< payload writing error, user-defined error 2 **/
    FOTA_STATUS_UNSUPPORTED                   = -508, /**< payload writing error, user-defined error 3 **/
    FOTA_STATUS_INTERNAL_ERROR                = -509, /**< payload writing error, user-defined error 4 **/
    FOTA_STATUS_INVALID_ARGUMENT              = -510, /**< payload writing error, user-defined error 5 **/
    FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED      = -511, /**< application rejected install authorization request */
    FOTA_STATUS_INSTALL_DEFER_UNSUPPORTED     = -513, /**< application deferred install when not supported */

} fota_status_e;


#ifdef __cplusplus
}
#endif

#endif  // __FOTA_STATUS_H_
