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
#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota.h"
#include "fota/fota_source.h"
#include "fota/fota_internal.h"
#include "fota/fota_event_handler.h"

#include <inttypes.h>

void fota_app_authorize(uint32_t token)
{
    fota_event_handler_defer_with_result(fota_on_authorize, token, 0);
}

void fota_app_reject(uint32_t token, int32_t reason)
{
    fota_event_handler_defer_with_result(fota_on_reject, token, reason);
}

void fota_app_defer(uint32_t token)
{
    fota_event_handler_defer_with_result(fota_on_defer, token, 0);
}

void fota_app_resume(void)
{
    fota_event_handler_defer_with_result(fota_on_resume, 0, 0);
}

FOTA_WEAK void fota_app_on_download_progress(uint32_t downloaded_size, uint32_t current_chunk_size, uint32_t total_size)
{
    FOTA_ASSERT(total_size);
    static const uint32_t  print_range_percent = 5;
    uint32_t progress = (downloaded_size + current_chunk_size) * 100 / total_size;
    uint32_t prev_progress = downloaded_size * 100 / total_size;

    if (downloaded_size == 0 || ((progress / print_range_percent) > (prev_progress / print_range_percent))) {
        FOTA_APP_PRINT("Downloading firmware. %" PRIu32 "%c", progress, '%');
    }
}

/* Pelion FOTA done or terminated.
 * Application can restore performance sensitive tasks and
 * dismiss any update running dialogs.
 *
*/
FOTA_WEAK int fota_app_on_complete(int32_t status)
{
    return FOTA_STATUS_SUCCESS;
}

/* Pelion FOTA Client wishes to reboot and apply the new firmware.

    The user application is supposed to save all current work
    before rebooting.

    Note: the authorization call can be postponed and called later.
    This doesn't affect the performance of the Cloud Client.
*/
FOTA_WEAK int fota_app_on_install_authorization(uint32_t token)
{
    fota_app_authorize(token);
    FOTA_APP_PRINT("Install authorization granted");
    return FOTA_STATUS_SUCCESS;
}

/* Pelion FOTA Client wishes to download new firmware.
    This can have a negative impact on the performance of the
    rest of the system.

    The user application is supposed to pause performance
    sensitive tasks before authorizing the download.

    Note: the authorization call can be postponed and called later.
    This doesn't affect the performance of the Cloud Client.
*/
FOTA_WEAK int fota_app_on_download_authorization(
    uint32_t token,
    const manifest_firmware_info_t *candidate_info,
    fota_component_version_t curr_fw_version
)
{
    FOTA_APP_PRINT("---------------------------------------------------");
    FOTA_APP_PRINT(
        "Updating component %s from version %" PRIu64 " to %" PRIu64,
        candidate_info->component_name,
        curr_fw_version,
        candidate_info->version
    );
    FOTA_APP_PRINT("Update priority %" PRIu32, candidate_info->priority);

    if (candidate_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        FOTA_APP_PRINT(
            "Delta update. Patch size %" PRIu32 "B full image size %" PRIu32 "B",
            candidate_info->payload_size,
            candidate_info->installed_size
        );
    } else {
        FOTA_APP_PRINT("Update size %" PRIu32 "B", candidate_info->payload_size);
    }
    FOTA_APP_PRINT("---------------------------------------------------");
    FOTA_APP_PRINT("Download authorization granted");
    fota_app_authorize(token);
    /* Application can reject an update in the following way
        fota_app_reject(token, 127);
        Reason error code will be logged.
       Alternatively application can defer the update by calling
        fota_app_defer(token);
       Deferred update will be restarted on next boot or by calling fota_app_resume() API.

    */
    return FOTA_STATUS_SUCCESS;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
