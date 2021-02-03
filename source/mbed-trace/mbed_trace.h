// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#ifndef MBED_TRACE_H
#define MBED_TRACE_H

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include "direct_serial_output.h"

#ifdef __cplusplus
extern "C" {
#endif

#undef tr_debug
#undef tr_info
#undef tr_warning
#undef tr_warn
#undef tr_error
#undef tr_trace
#undef tr_flush


#if (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_PRINTF)
#if MBED_BOOTLOADER_DEBUG_PRINTS_ENABLED
#define pr_debug(fmt, ...)   printf("[DBG ] " fmt "\r\n", ##__VA_ARGS__)
#else
#define pr_debug(...)
#endif

#define pr_info(fmt, ...)    printf("[BOOT] " fmt "\r\n", ##__VA_ARGS__)

#define pr_warning(fmt, ...) printf("[WARN] " fmt "\r\n", ##__VA_ARGS__)

#define pr_error(fmt, ...)   printf("[ERR ] " fmt "\r\n", ##__VA_ARGS__)

#define pr_trace(fmt, ...)   printf(fmt, ##__VA_ARGS__)

#define pr_flush(x)

#else
#define pr_debug(...)

#define pr_info(fmt, ...)    direct_serial_output_process("[BOOT] " fmt "\r\n")

#define pr_warning(fmt, ...) direct_serial_output_process("[WARN] " fmt "\r\n")

#define pr_error(fmt, ...)   direct_serial_output_process("[ERR ] " fmt "\r\n")

#define pr_trace(fmt, ...)   direct_serial_output_process(fmt)

#define pr_flush(x)

#endif

#if MBED_BOOTLOADER_EXTERNAL_TRACES_ENABLED
#define tr_debug    pr_debug
#define tr_info     pr_info
#define tr_warning  pr_warning
#define tr_warn     pr_warning
#define tr_error    pr_error
#define tr_trace    pr_trace
#define tr_flush    pr_flush
#else
#define tr_debug(...)
#define tr_info(...)
#define tr_warning(...)
#define tr_warn(...)
#define tr_error(...)
#define tr_trace(...)
#define tr_flush(...)
#endif
#define tr_array
#define tr_ipv6
#define tr_ipv6_prefix
#define trace_array
#define trace_ipv6
#define trace_ipv6_prefix

#ifdef __cplusplus
}
#endif

#endif // MBED_TRACE_H
