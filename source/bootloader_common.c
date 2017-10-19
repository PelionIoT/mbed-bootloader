//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2016-2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

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
void printSHA256(const uint8_t SHA[PAL_SHA256_SIZE])
{
    /* allocate space for string */
    char buffer[2 * PAL_SHA256_SIZE + 1] = { 0 };

    for (uint_least8_t index = 0; index < PAL_SHA256_SIZE; index++)
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
