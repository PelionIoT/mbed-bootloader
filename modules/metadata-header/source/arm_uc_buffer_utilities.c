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

#include "update-client-metadata-header/arm_uc_buffer_utilities.h"


uint32_t arm_uc_crc32(const uint8_t *buffer, uint32_t length)
{
    const uint8_t *current = buffer;
    uint32_t crc = 0xFFFFFFFF;

    while (length--) {
        crc ^= *current++;

        for (uint32_t counter = 0; counter < 8; counter++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }

    return (crc ^ 0xFFFFFFFF);
}

uint32_t arm_uc_parse_uint32(const uint8_t *input)
{
    uint32_t result = 0;

    if (input) {
        result = input[0];
        result = (result << 8) | input[1];
        result = (result << 8) | input[2];
        result = (result << 8) | input[3];
    }

    return result;
}

uint64_t arm_uc_parse_uint64(const uint8_t *input)
{
    uint64_t result = 0;

    if (input) {
        result = input[0];
        result = (result << 8) | input[1];
        result = (result << 8) | input[2];
        result = (result << 8) | input[3];
        result = (result << 8) | input[4];
        result = (result << 8) | input[5];
        result = (result << 8) | input[6];
        result = (result << 8) | input[7];
    }

    return result;
}

void arm_uc_write_uint32(uint8_t *buffer, uint32_t value)
{
    if (buffer) {
        buffer[3] = value;
        buffer[2] = (value >> 8);
        buffer[1] = (value >> 16);
        buffer[0] = (value >> 24);
    }
}

void arm_uc_write_uint64(uint8_t *buffer, uint64_t value)
{
    if (buffer) {
        buffer[7] = value;
        buffer[6] = (value >> 8);
        buffer[5] = (value >> 16);
        buffer[4] = (value >> 24);
        buffer[3] = (value >> 32);
        buffer[2] = (value >> 40);
        buffer[1] = (value >> 48);
        buffer[0] = (value >> 56);
    }
}

// Constant time binary comparison
uint32_t ARM_UC_BinCompareCT(const arm_uc_buffer_t *a, const arm_uc_buffer_t *b)
{
    uint32_t result;
    uint32_t i;
    const uint32_t bytes = a->size;

    // Check sizes
    if (a->size != b->size) {
        return 1;
    }
    result = 0;
    for (i = 0; i < bytes; i++) {
        result = result | (a->ptr[i] ^ b->ptr[i]);
    }
    // Reduce to 0 or 1 in constant time
    return (result | -result) >> 31;
}
