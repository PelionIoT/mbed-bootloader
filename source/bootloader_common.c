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
                           '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                          };


#if DEVICE_SERIAL && SHOW_SERIAL_OUTPUT

#include "hal/serial_api.h"

static serial_t stdio_uart = { 0 };

/* module variable for keeping track of initialization */
static bool not_initialized = true;

/**
 * @brief Initialization serial port if needed.
 *.
 */
static void init_serial()
{
    if (not_initialized)
    {
        not_initialized = false;

        serial_init(&stdio_uart, STDIO_UART_TX, STDIO_UART_RX);
#if MBED_CONF_PLATFORM_STDIO_BAUD_RATE
        serial_baud(&stdio_uart, MBED_CONF_PLATFORM_STDIO_BAUD_RATE);
#endif
    }

}

/**
 * @brief Function that directly outputs to serial port in blocking mode.
 *
 * @param string outputed to serial port.
 */
void boot_debug(const char *s)
{
    init_serial();

    while(*s) {
        serial_putc(&stdio_uart, *s);
        s++;
    }
}

#else

/**
 * @brief Fake function for boot debug.
 *
 * @param unused.
 */
void boot_debug(const char *s)
{
    (void)s;
}

#endif // DEVICE_SERIAL && SHOW_SERIAL_OUTPUT

/**
 * @brief Event handler for UCP callbacks.
 *
 * @param event Event
 */
void arm_ucp_event_handler(uint32_t event)
{
    event_callback = event;
}

/**
 * Helper function to print a SHA-256 in a nice format.
 * @param [in]  SHA  The array of PAL_SHA256_SIZE containing the SHA256
 */
void print_sha256_function(const uint8_t SHA[SIZEOF_SHA256])
{
    /* allocate space for string */
    char buffer[2 * SIZEOF_SHA256 + 1] = { 0 };

    for (uint_least8_t index = 0; index < SIZEOF_SHA256; index++) {
        uint8_t value = SHA[index];

        buffer[2 * index]     = hexTable[value >> 4];
        buffer[2 * index + 1] = hexTable[value & 0x0F];
    }
}

void print_progress_function(uint32_t progress, uint32_t total)
{
    static uint8_t last_percent = 0;

    /* use 70 characters for the progress bar */
    uint8_t percent = progress * 70 / total;

    if (last_percent != percent) {
        last_percent = percent;
        boot_debug("\r[BOOT] [");

        /* print + for progress or a space otherwise */
        for (uint8_t index = 0; index < 70; index++) {
            if (index <= percent) {
                boot_debug("+");
            } else {
                boot_debug(" ");
            }
        }

        /* finish progress bar with a newline once complete */
        if (progress >= total) {
            boot_debug("]\r\n");
        } else {
            boot_debug("]");

            /* explicitly flush debug channel, usually this is triggered by \n */
            tr_flush();
        }
    }
}
