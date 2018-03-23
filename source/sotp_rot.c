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

#if defined(ARM_UC_USE_SOTP) && ARM_UC_USE_SOTP == 1

#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include "pal.h"
#include "sotp.h"

#define DEVICE_KEY_SIZE_IN_BYTES (128/8)

/* We can get the RoT from SOTP using either sotp_probe (when ARM_UC_SOTP_PROBE_ONLY is defined to 1)
 * or the "regular" sotp_get function (when ARM_UC_SOTP_PROBE_ONLY is not defined or is defined to 0)
 */
#if defined(ARM_UC_SOTP_PROBE_ONLY) && ARM_UC_SOTP_PROBE_ONLY == 1
#define SOTP_GET_FUNCTION sotp_probe
#else
#define SOTP_GET_FUNCTION sotp_get
#endif

/**
 * @brief Function to get the device root of trust
 * @details The device root of trust should be a 128 bit value. It should never leave the device.
 *          It should be unique to the device. It should have enough entropy to avoid contentional
 *          entropy attacks. The porter should implement the following device signature to provide
 *          device root of trust on different platforms.
 *
 * @param key_buf buffer to be filled with the device root of trust.
 * @param length  length of the buffer provided to make sure no overflow occurs.
 *
 * @return 0 on success, non-zero on failure.
 */

int8_t mbed_cloud_client_get_rot_128bit(uint8_t *key_buf, uint32_t length)
{
    static bool initialized = false;
    uint32_t rot[DEVICE_KEY_SIZE_IN_BYTES / sizeof(uint32_t)];
    uint16_t actual_len_bytes = 0;

    if (length < DEVICE_KEY_SIZE_IN_BYTES || key_buf == NULL)
    {
        return -1;
    }

    if (!initialized)
    {
#if !defined(ARM_UC_SOTP_PROBE_ONLY) || ARM_UC_SOTP_PROBE_ONLY == 0 // sotp_probe doesn't need sotp_init()
        if (pal_internalFlashInit() != PAL_SUCCESS)
        {
            return -1;
        }
#endif
        initialized = true;
    }
    sotp_result_e status = SOTP_GET_FUNCTION(SOTP_TYPE_ROT, DEVICE_KEY_SIZE_IN_BYTES, rot, &actual_len_bytes);
    if (status != SOTP_SUCCESS || actual_len_bytes != DEVICE_KEY_SIZE_IN_BYTES)
    {
        return -1;
    }
    memcpy(key_buf, rot, DEVICE_KEY_SIZE_IN_BYTES);
    return 0;
}

#endif // #if defined(ARM_UC_USE_SOTP) && ARM_UC_USE_SOTP == 1
