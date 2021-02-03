// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#include "direct_serial_output.h"
#include "hal/serial_api.h"

#if (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_DIRECT_SERIAL_OUTPUT)

static serial_t uart = {};

/* module variable for keeping track of initialization */
static bool not_initialized = true;

/**
 * @brief Initialization serial port if needed.
 *.
 */
static void direct_serial_output_init()
{
    if (not_initialized)
    {
        not_initialized = false;

        serial_init(&uart, STDIO_UART_TX, STDIO_UART_RX);
#if MBED_CONF_PLATFORM_STDIO_BAUD_RATE
        serial_baud(&uart, MBED_CONF_PLATFORM_STDIO_BAUD_RATE);
#endif
    }
}

/**
 * @brief Function that directly outputs to serial port in blocking mode.
 *
 * @param string outputed to serial port.
 */
void direct_serial_output_process(const char *s)
{
    direct_serial_output_init();

    while(*s) {
        serial_putc(&uart, *s);
        s++;
    }
}

#endif // MBED_BOOTLOADER_USE_DIRECT_SERIAL_OUTPUT

