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
#include "arm_uc_paal_update_api.h"

/* use a cut down version of ARM_UCP_FLASHIAP_BLOCKDEVICE to reduce
   binary size if ARM_UC_USE_PAL_BLOCKDEVICE is set */
#if defined(ARM_UC_USE_PAL_BLOCKDEVICE) && (ARM_UC_USE_PAL_BLOCKDEVICE==1)
#undef  MBED_CLOUD_CLIENT_UPDATE_STORAGE
#define MBED_CLOUD_CLIENT_UPDATE_STORAGE ARM_UCP_FLASHIAP_BLOCKDEVICE_READ_ONLY
#endif

#ifdef MBED_CLOUD_CLIENT_UPDATE_STORAGE
extern ARM_UC_PAAL_UPDATE MBED_CLOUD_CLIENT_UPDATE_STORAGE;
#else
#error Update client storage must be defined in user configuration file
#endif

#ifndef MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS
#error Application start address must be defined
#endif

/* If jump address is not set then default to start address. */
#ifndef MBED_CONF_APP_APPLICATION_JUMP_ADDRESS
#define MBED_CONF_APP_APPLICATION_JUMP_ADDRESS MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS
#endif

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

void boot_debug(const char *s);

#define MBED_BOOTLOADER_ASSERT(condition, ...) { \
    if (!(condition)) {                          \
        boot_debug("[ERR ] ASSERT\r\n");                   \
        /* coverity[no_escape] */                \
        while (1) __WFI();                       \
    }                                            \
}


#if SHOW_SERIAL_OUTPUT
#define printSHA256 print_sha256_function
#define printProgress print_progress_function
#else
#define printSHA256
#define printProgress
#endif

#if MBED_CONF_MBED_TRACE_ENABLE

#ifndef SHOW_SERIAL_OUTPUT
#define SHOW_SERIAL_OUTPUT 1
#endif

#else

#ifdef tr_debug
#undef tr_debug
#endif
#define tr_debug(...)

#ifdef tr_info
#undef tr_info
#endif
#define tr_info(...)

#ifdef tr_warning
#undef tr_warning
#endif
#define tr_warning(...)

#ifdef tr_error
#undef tr_error
#endif
#define tr_error(...)

#ifdef tr_trace
#undef tr_trace
#endif
#define tr_trace(...)

#ifdef tr_flush
#undef tr_flush
#endif
#define tr_flush(x)

#endif

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_COMMON_H
