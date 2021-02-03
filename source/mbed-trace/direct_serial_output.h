// ----------------------------------------------------------------------------
// Copyright 2020 Pelion Ltd.
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

#ifndef DIRECT_SERIAL_OUTPUT_H
#define DIRECT_SERIAL_OUTPUT_H

#include <stdint.h>

#define USE_PRINTF 5555
#define USE_DIRECT_SERIAL_OUTPUT 5556

#if (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_DIRECT_SERIAL_OUTPUT)

#ifdef __cplusplus
extern "C" {
#endif

void direct_serial_output_process(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif // (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_DIRECT_SERIAL_OUTPUT)

#endif // DIRECT_SERIAL_OUTPUT_H
