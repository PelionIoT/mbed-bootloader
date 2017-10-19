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

#ifndef BOOTLOADER_COMMON_H
#define BOOTLOADER_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h"

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 16 * 1024
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

#define ASSERT(condition, ...)  {               \
    if (!(condition)) {                         \
        tr_error(__VA_ARGS__);                  \
        while (1) __WFI();                      \
    }                                           \
}

/* if the global trace flag is not enabled, use printf directly */
#if !defined(MBED_CONF_MBED_TRACE_ENABLE) || MBED_CONF_MBED_TRACE_ENABLE == 0

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>

#if 0
#define tr_debug(fmt, ...)   printf("[DBG ] " fmt "\r\n", ##__VA_ARGS__)
#else
#define tr_debug(...)
#endif

#define tr_info(fmt, ...)    printf("[BOOT] " fmt "\r\n", ##__VA_ARGS__)
#define tr_warning(fmt, ...) printf("[WARN] " fmt "\r\n", ##__VA_ARGS__)
#define tr_error(fmt, ...)   printf("[ERR ] " fmt "\r\n", ##__VA_ARGS__)
#define tr_trace(fmt, ...)   printf(fmt, ##__VA_ARGS__)
#define tr_flush(x)          fflush(stdout)

#endif

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_COMMON_H
