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

#ifndef BOOTLOADER_COMMON_H
#define BOOTLOADER_COMMON_H

#include <stdint.h>
#include "bootloader_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SIZEOF_SHA256  (256/8)

#ifndef BUFFER_SIZE
#define BUFFER_SIZE (16 * 1024)
#endif

#define CLEAR_EVENT 0xFFFFFFFF

enum {
    RESULT_SUCCESS,
    RESULT_ERROR,
    RESULT_EMPTY
};

extern uint8_t buffer_array[BUFFER_SIZE];

extern uint32_t event_callback;
extern const char hexTable[16];

void arm_ucp_event_handler(uint32_t event);

void printSHA256(const uint8_t SHA[SIZEOF_SHA256]);

void printProgress(uint32_t progress, uint32_t total);

#define MBED_BOOTLOADER_ASSERT(condition, ...) { \
    if (!(condition)) {                          \
        tr_error(__VA_ARGS__);                   \
        /* coverity[no_escape] */                \
        while (1) __WFI();                       \
    }                                            \
}

/* if the global trace flag is not enabled, use printf directly */
#if !defined(MBED_CONF_MBED_TRACE_ENABLE) || MBED_CONF_MBED_TRACE_ENABLE == 0

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>

#ifdef tr_debug
#undef tr_debug
#endif
#if 0
#define tr_debug(fmt, ...)   printf("[DBG ] " fmt "\r\n", ##__VA_ARGS__)
#else
#define tr_debug(...)
#endif

#ifdef tr_info
#undef tr_info
#endif
#define tr_info(fmt, ...)    printf("[BOOT] " fmt "\r\n", ##__VA_ARGS__)

#ifdef tr_warning
#undef tr_warning
#endif
#define tr_warning(fmt, ...) printf("[WARN] " fmt "\r\n", ##__VA_ARGS__)

#ifdef tr_error
#undef tr_error
#endif
#define tr_error(fmt, ...)   printf("[ERR ] " fmt "\r\n", ##__VA_ARGS__)

#ifdef tr_trace
#undef tr_trace
#endif
#define tr_trace(fmt, ...)   printf(fmt, ##__VA_ARGS__)

#ifdef tr_flush
#undef tr_flush
#endif
// Disable flushing if mbed-printf is used, since mbed-printf is not buffered
#ifdef MBED_CONF_MINIMAL_PRINTF_ENABLE_FLOATING_POINT
#define tr_flush(x)
#else
#define tr_flush(x)          fflush(stdout)
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_COMMON_H
