// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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

#ifndef __FOTA_BASE_H_
#define __FOTA_BASE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "fota/fota_config.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifndef MIN
#define MIN(A, B) ((A) < (B) ? (A) : (B))
#endif
#ifndef MAX
#define MAX(A, B) ((A) > (B) ? (A) : (B))
#endif

#if defined(__ICCARM__)
#define FOTA_WEAK __weak
#elif defined(__MINGW32__)
#define FOTA_WEAK
#else
#define FOTA_WEAK __attribute__((weak))
#endif

#if MBED_CONF_MBED_TRACE_ENABLE
#include "mbed-trace/mbed_trace.h"
#define FOTA_TRACE_DEBUG tr_debug
#define FOTA_TRACE_INFO  tr_info
#define FOTA_TRACE_ERROR tr_error
#else

#if FOTA_TRACE_ENABLE
#if FOTA_TRACE_DBG
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define FOTA_TRACE_DEBUG(fmt, ...) printf("[FOTA DEBUG] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define FOTA_TRACE_INFO(fmt, ...)  printf("[FOTA INFO] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define FOTA_TRACE_ERROR(fmt, ...) printf("[FOTA ERROR] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#else  // !FOTA_TRACE_DBG
#define FOTA_TRACE_DEBUG(fmt, ...)
#define FOTA_TRACE_INFO(fmt, ...)  printf("[FOTA INFO] " fmt "\n", ##__VA_ARGS__)
#define FOTA_TRACE_ERROR(fmt, ...) printf("[FOTA ERROR] " fmt "\n", ##__VA_ARGS__)
#endif  // FOTA_TRACE_DBG
#else  // FOTA_TRACE_ENABLE
#define FOTA_TRACE_DEBUG(fmt, ...)
#define FOTA_TRACE_INFO(fmt, ...)
#define FOTA_TRACE_ERROR(fmt, ...)
#endif  // !FOTA_TRACE_ENABLE
#endif  // !MBED_CONF_MBED_TRACE_ENABLE

#if FOTA_APP_DEFAULT_CB_NO_PRINT || MBED_DISABLE_PRINTFS
#define FOTA_APP_PRINT FOTA_TRACE_INFO
#else
#define FOTA_APP_PRINT(fmt, ...)  printf("[FOTA] " fmt "\n", ##__VA_ARGS__)
#endif

#if !defined(FOTA_HALT)
#if defined(FOTA_UNIT_TEST)
void unitest_halt(void);
#define FOTA_HALT unitest_halt()
#elif defined(TARGET_LIKE_LINUX)
#define FOTA_HALT assert(0)
#else
#define FOTA_HALT for(;;)
#endif
#endif

#define FOTA_ASSERT(COND) { \
    if (!(COND)) { \
        FOTA_TRACE_ERROR("Assertion failed: FOTA_ASSERT(%s)", #COND); \
        FOTA_HALT; \
    } \
}

#if defined(NDEBUG)
#define FOTA_DBG_ASSERT(COND) ((void)0)
#else
#define FOTA_DBG_ASSERT FOTA_ASSERT
#endif

#define FOTA_ALIGN_UP(val, size)  (((((val) - 1) / (size)) + 1) * (size))

#define FOTA_ALIGN_DOWN(val, size)  ((val) / (size) * (size))


#if defined(__GNUC__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define FOTA_UINT64_TO_LE  __builtin_bswap64
#else
#define FOTA_UINT64_TO_LE
#endif


#ifdef __cplusplus
}
#endif

#endif // __FOTA_BASE_H_
