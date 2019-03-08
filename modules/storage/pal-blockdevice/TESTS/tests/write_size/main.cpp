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

#include <mbed.h>
#include <mbedtls/sha256.h>
#include <sd-driver/SDBlockDevice.h>

#include <greentea-client/test_env.h>
#include <utest/utest.h>
#include <unity/unity.h>

#include "update-client-paal/arm_uc_paal_update.h"

using namespace utest::v1;

#include "pal_plat_rtos.h"

palStatus_t  pal_plat_osGetRoT128Bit(uint8_t *keyBuf, size_t keyLenBytes)
{
    return PAL_SUCCESS;
}

#define SIZEOF_SHA256 256/8
/* lookup table for printing hexadecimal values */
const char hexTable[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                          };

/**
 * Helper function to print a SHA-256 in a nice format.
 * @param [in]  SHA  The array of PAL_SHA256_SIZE containing the SHA256
 */
void printSHA256(const uint8_t SHA[SIZEOF_SHA256])
{
    /* allocate space for string */
    char buffer[2 * SIZEOF_SHA256 + 1] = { 0 };

    for (uint_least8_t index = 0; index < SIZEOF_SHA256; index++) {
        uint8_t value = SHA[index];

        buffer[2 * index]     = hexTable[value >> 4];
        buffer[2 * index + 1] = hexTable[value & 0x0F];
    }

    printf("SHA256: %s\r\n", buffer);
}

extern ARM_UC_PAAL_UPDATE ARM_UCP_FLASHIAP_BLOCKDEVICE;

#if defined (MBED_CONF_APP_SPI_MOSI) && defined (MBED_CONF_APP_SPI_MISO) && defined (MBED_CONF_APP_SPI_CLK) && defined (MBED_CONF_APP_SPI_CS)
SDBlockDevice sd(MBED_CONF_APP_SPI_MOSI, MBED_CONF_APP_SPI_MISO, MBED_CONF_APP_SPI_CLK, MBED_CONF_APP_SPI_CS);
#else
SDBlockDevice sd(MBED_CONF_SD_SPI_MOSI, MBED_CONF_SD_SPI_MISO, MBED_CONF_SD_SPI_CLK, MBED_CONF_SD_SPI_CS);
#endif

BlockDevice *arm_uc_blockdevice = &sd;
volatile uint8_t event_received = 0;

void callback(uint32_t event)
{
    switch (event) {
        case ARM_UC_PAAL_EVENT_INITIALIZE_DONE:
        case ARM_UC_PAAL_EVENT_PREPARE_DONE:
        case ARM_UC_PAAL_EVENT_WRITE_DONE:
        case ARM_UC_PAAL_EVENT_FINALIZE_DONE:
        case ARM_UC_PAAL_EVENT_READ_DONE:
        case ARM_UC_PAAL_EVENT_ACTIVATE_DONE:
        case ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE:
        case ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE:
        case ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE:
            event_received = 1;
            break;
        default:
            break;
    }
}

void test_unit()
{
    uint32_t program_size = arm_uc_blockdevice->get_program_size();
    TEST_ASSERT_TRUE(program_size > 0);

    /* setup firmware size unaligned to page size */
    uint32_t firmware_size = program_size * 10 - 1;
    uint32_t BUFFER_SIZE = program_size * 3;
    uint8_t buf[BUFFER_SIZE] = {0};
    uint8_t storage_location = 0;

    event_received = 0;
    arm_uc_error_t err = ARM_UCP_FLASHIAP_BLOCKDEVICE.Initialize(callback);
    TEST_ASSERT_EQUAL_HEX(ERR_NONE, err.code);
    while (!event_received) { __WFI(); }

    /* firmware details struct */
    arm_uc_firmware_details_t details = { 0 };

    memset(details.hash, 0xff, SIZEOF_SHA256);
    details.version = 0;
    details.size = firmware_size;

    arm_uc_buffer_t buffer = {
        .size_max = BUFFER_SIZE,
        .size = 0,
        .ptr = buf
    };

    event_received = 0;
    err = ARM_UCP_FLASHIAP_BLOCKDEVICE.Prepare(storage_location, &details, &buffer);
    TEST_ASSERT_EQUAL_HEX(ERR_NONE, err.code);
    while (!event_received) { __WFI(); }

    /* prepare hash context */
    unsigned char write_hash[SIZEOF_SHA256];
    unsigned char read_hash[SIZEOF_SHA256];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);

    /* write firmware to storage */
    uint32_t offset = 0;
    while (offset < details.size) {
        buffer.size = (details.size - offset) > buffer.size_max ? buffer.size_max : details.size - offset;

        /* generate some pseudo random data */
        for (int i = 0; i < buffer.size; i += SIZEOF_SHA256) {
            mbedtls_sha256(buffer.ptr, buffer.size_max, write_hash, 0);
            uint32_t copy_size = buffer.size - i < SIZEOF_SHA256 ? buffer.size - i : SIZEOF_SHA256;
            memcpy(&buffer.ptr[i], write_hash, copy_size);
        }

        printf("writing %u bytes at offset %u\r\n", buffer.size, offset);
        event_received = 0;
        err = ARM_UCP_FLASHIAP_BLOCKDEVICE.Write(storage_location, offset, &buffer);
        TEST_ASSERT_EQUAL_HEX(ERR_NONE, err.code);
        while (!event_received) { __WFI(); }
        offset += buffer.size;

        mbedtls_sha256_update(&ctx, buffer.ptr, buffer.size);
    }

    mbedtls_sha256_finish(&ctx, write_hash);

    event_received = 0;
    err = ARM_UCP_FLASHIAP_BLOCKDEVICE.Finalize(storage_location);
    TEST_ASSERT_EQUAL_HEX(ERR_NONE, err.code);
    while (!event_received) { __WFI(); }

    /* read firmware back */
    offset = 0;
    mbedtls_sha256_starts(&ctx, 0);
    while (offset < details.size) {
        buffer.size = (details.size - offset) > buffer.size_max ? buffer.size_max : details.size - offset;


        printf("reading %u bytes at offset %u\r\n", buffer.size, offset);
        event_received = 0;
        err = ARM_UCP_FLASHIAP_BLOCKDEVICE.Read(storage_location, offset, &buffer);
        TEST_ASSERT_EQUAL_HEX(ERR_NONE, err.code);
        while (!event_received) { __WFI(); }
        offset += buffer.size;

        mbedtls_sha256_update(&ctx, buffer.ptr, buffer.size);
    }

    mbedtls_sha256_finish(&ctx, read_hash);

    printSHA256(write_hash);
    printSHA256(read_hash);
    TEST_ASSERT_EQUAL_MEMORY(write_hash, read_hash, sizeof(write_hash));
}

Case cases[] = {
    Case("test_write_size", test_unit)
};

utest::v1::status_t greentea_setup(const size_t number_of_cases)
{
#if defined(TARGET_LIKE_MBED)
    GREENTEA_SETUP(60, "default_auto");
#endif
    return greentea_test_setup_handler(number_of_cases);
}

Specification specification(greentea_setup, cases);

#if defined(TARGET_LIKE_MBED)
int main()
#elif defined(TARGET_LIKE_POSIX)
void app_start(int argc __unused, char **argv __unused)
#endif
{
    // Run the test specification
    Harness::run(specification);
}
