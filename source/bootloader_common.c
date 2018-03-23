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

#include "bootloader_common.h"

/* buffer used in storage operations */
uint8_t buffer_array[BUFFER_SIZE];

/* variable for exposing the most recent event */
uint32_t event_callback = CLEAR_EVENT;

/* lookup table for printing hexadecimal values */
const char hexTable[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

/**
 * @brief Event handler for UCP callbacks.
 *
 * @param event Event
 */
void arm_ucp_event_handler(uint32_t event)
{
    tr_debug("event: %" PRIx32, event);

    event_callback = event;
}

/**
 * Helper function to print a SHA-256 in a nice format.
 * @param [in]  SHA  The array of PAL_SHA256_SIZE containing the SHA256
 */
void printSHA256(const uint8_t SHA[SIZEOF_SHA256])
{
    /* allocate space for string */
    char buffer[2 * SIZEOF_SHA256 + 1] = { 0 };

    for (uint_least8_t index = 0; index < SIZEOF_SHA256; index++)
    {
        uint8_t value = SHA[index];

        buffer[2 * index]     = hexTable[value >> 4];
        buffer[2 * index + 1] = hexTable[value & 0x0F];
    }

    tr_info("SHA256: %s", buffer);
}

void printProgress(uint32_t progress, uint32_t total)
{
    static uint8_t last_percent = 0;

    /* use 70 characters for the progress bar */
    uint8_t percent = progress * 70 / total;

    if (last_percent != percent)
    {
        last_percent = percent;
        tr_trace("\r[BOOT] [");

        /* print + for progress or a space otherwise */
        for (uint8_t index = 0; index < 70; index++)
        {
            if (index <= percent)
            {
                tr_trace("+");
            }
            else
            {
                tr_trace(" ");
            }
        }

        /* finish progress bar with a newline once complete */
        if (progress >= total)
        {
            tr_trace("]\r\n");
        }
        else
        {
            tr_trace("]");

            /* explicitly flush debug channel, usually this is triggered by \n */
            tr_flush();
        }
    }
}
