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

#ifndef ARM_UPDATE_BUFFER_UTILITIES_H
#define ARM_UPDATE_BUFFER_UTILITIES_H

#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_error.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Calculate CRC 32
 *
 * @param buffer Input array.
 * @param length Length of array in bytes.
 *
 * @return 32 bit CRC.
 */
uint32_t arm_uc_crc32(const uint8_t *buffer, uint32_t length);

/**
 * @brief Parse 4 byte array into uint32_t
 *
 * @param input 4 byte array.
 * @return uint32_t
 */
uint32_t arm_uc_parse_uint32(const uint8_t *input);

/**
 * @brief Parse 8 byte array into uint64_t
 *
 * @param input 8 byte array.
 * @return uint64_t
 */
uint64_t arm_uc_parse_uint64(const uint8_t *input);

/**
 * @brief Write uint32_t to array.
 *
 * @param buffer Pointer to buffer.
 * @param value Value to be written.
 */
void arm_uc_write_uint32(uint8_t *buffer, uint32_t value);

/**
 * @brief Write uint64_t to array.
 *
 * @param buffer Pointer to buffer.
 * @param value Value to be written.
 */
void arm_uc_write_uint64(uint8_t *buffer, uint64_t value);


uint32_t ARM_UC_BinCompareCT(const arm_uc_buffer_t *a, const arm_uc_buffer_t *b);

#ifdef __cplusplus
}
#endif

#endif // ARM_UPDATE_BUFFER_UTILITIES_H
