/*
 * mbed Microcontroller Library
 * Copyright (c) 2006-2016 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file fopen.cpp Test cases to POSIX file fopen() interface.
 *
 * Please consult the documentation under the test-case functions for
 * a description of the individual test case.
 */

#include "mbed.h"

#include "utest/utest.h"
#include "unity/unity.h"
#include "greentea-client/test_env.h"

#include "mbedtls/entropy_poll.h"
#include "mbedtls/md.h"

#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_error.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

extern "C" arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key, arm_uc_buffer_t *input,
                                                  arm_uc_buffer_t *output);

using namespace utest::v1;

#define SHA256_BLOCK_SIZE (64)
#define KEY_SIZE (32)
#define DATA_SIZE (1024)
#define HASH_SIZE (32)

#include "nist_cavs_1.h"
#include "nist_cavs_2.h"
#include "nist_cavs_3.h"
#include "nist_cavs_4.h"
#include "nist_cavs_5.h"
#include "nist_cavs_6.h"

#if !DEVICE_TRNG
#error [NOT_SUPPORTED] TRNG API not supported for this target
#else

static uint8_t key_array[KEY_SIZE] = { 0 };
static uint8_t data_array[DATA_SIZE] = { 0 };

static uint8_t hash_mbedtls[HASH_SIZE] = { 0 };
static uint8_t hash_bootloader[HASH_SIZE] = { 0 };

static control_t test_unit(const size_t call_count)
{
    arm_uc_error_t result;

    arm_uc_buffer_t key_buffer = { 0 };
    arm_uc_buffer_t input_buffer = { 0 };
    arm_uc_buffer_t output_buffer = { 0 };

    /**
     * Test invalid buffers.
     */
    result = ARM_UC_cryptoHMACSHA256(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, NULL, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, NULL, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, &input_buffer, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, NULL, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    /**
     * Test buffer pointers missing underlying buffers.
     */
    key_buffer.ptr = key_array;
    input_buffer.ptr = data_array;
    output_buffer.ptr = hash_bootloader;

    result = ARM_UC_cryptoHMACSHA256(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, NULL, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, NULL, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, &input_buffer, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, NULL, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    /**
     * Test valid buffer pointers.
     */
    key_buffer.size_max = KEY_SIZE;
    input_buffer.size_max = DATA_SIZE;
    output_buffer.size_max = HASH_SIZE;

    /* ARM_UC_CU_ERR_INVALID_PARAMETER */
    result = ARM_UC_cryptoHMACSHA256(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, NULL, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(&key_buffer, NULL, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, &input_buffer, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    result = ARM_UC_cryptoHMACSHA256(NULL, NULL, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code,
                                  "bootloader hmac returned wrong error code");

    /* ERR_NONE */
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "valid input should have succeeded");

    /**
     * Test key length.
     */
    uint8_t largekey[SHA256_BLOCK_SIZE];
    key_buffer.ptr = largekey;
    key_buffer.size = SHA256_BLOCK_SIZE;
    key_buffer.size_max = SHA256_BLOCK_SIZE;

    /* max key size */
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "valid input should have succeeded");

    /* max key size plus 1 */
    key_buffer.size = SHA256_BLOCK_SIZE + 1;
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ARM_UC_CU_ERR_INVALID_PARAMETER, result.code, "too large key size should have failed");

    return CaseNext;
}

static control_t test_nist_vectors(const size_t call_count)
{
    int retval = -1;

    /**
     * Verify mbedtls HMAC SHA 256 works with NIST test vectors.
     */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #1 */
    memset(hash_bootloader, 0, HASH_SIZE);
    retval = mbedtls_md_hmac(md_info,
                             nist_cavs_1_key, nist_cavs_1_key_len,
                             nist_cavs_1_msg, nist_cavs_1_msg_len,
                             hash_bootloader);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "mbedtls wrong return value");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_1_hmac, hash_bootloader, nist_cavs_1_hmac_len,
                                          "mbedtls hmac incorrect");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #2 */
    memset(hash_bootloader, 0, HASH_SIZE);
    retval = mbedtls_md_hmac(md_info,
                             nist_cavs_2_key, nist_cavs_2_key_len,
                             nist_cavs_2_msg, nist_cavs_2_msg_len,
                             hash_bootloader);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "mbedtls wrong return value");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_2_hmac, hash_bootloader, nist_cavs_2_hmac_len,
                                          "mbedtls hmac incorrect");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #3 */
    memset(hash_bootloader, 0, HASH_SIZE);
    retval = mbedtls_md_hmac(md_info,
                             nist_cavs_3_key, nist_cavs_3_key_len,
                             nist_cavs_3_msg, nist_cavs_3_msg_len,
                             hash_bootloader);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "mbedtls wrong return value");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_3_hmac, hash_bootloader, nist_cavs_3_hmac_len,
                                          "mbedtls hmac incorrect");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #4 */
    memset(hash_bootloader, 0, HASH_SIZE);
    retval = mbedtls_md_hmac(md_info,
                             nist_cavs_4_key, nist_cavs_4_key_len,
                             nist_cavs_4_msg, nist_cavs_4_msg_len,
                             hash_bootloader);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "mbedtls wrong return value");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_4_hmac, hash_bootloader, nist_cavs_4_hmac_len,
                                          "mbedtls hmac incorrect");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #5 */
    memset(hash_bootloader, 0, HASH_SIZE);
    retval = mbedtls_md_hmac(md_info,
                             nist_cavs_5_key, nist_cavs_5_key_len,
                             nist_cavs_5_msg, nist_cavs_5_msg_len,
                             hash_bootloader);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "mbedtls wrong return value");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_5_hmac, hash_bootloader, nist_cavs_5_hmac_len,
                                          "mbedtls hmac incorrect");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #6 */
    memset(hash_bootloader, 0, HASH_SIZE);
    retval = mbedtls_md_hmac(md_info,
                             nist_cavs_6_key, nist_cavs_6_key_len,
                             nist_cavs_6_msg, nist_cavs_6_msg_len,
                             hash_bootloader);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "mbedtls wrong return value");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_6_hmac, hash_bootloader, nist_cavs_6_hmac_len,
                                          "mbedtls hmac incorrect");

    /**
     * Use test vectors on ARM_UC_cryptoHMACSHA256.
     */
    arm_uc_error_t result;
    arm_uc_buffer_t key_buffer = { 0 };
    arm_uc_buffer_t input_buffer = { 0 };
    arm_uc_buffer_t output_buffer = { 0 };
    output_buffer.size = 0;
    output_buffer.size_max = HASH_SIZE;
    output_buffer.ptr = hash_bootloader;

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #1 */
    key_buffer.size = nist_cavs_1_key_len;
    key_buffer.size_max = nist_cavs_1_key_len;
    key_buffer.ptr = nist_cavs_1_key;

    input_buffer.size = nist_cavs_1_msg_len;
    input_buffer.size_max = nist_cavs_1_msg_len;
    input_buffer.ptr = nist_cavs_1_msg;

    memset(hash_bootloader, 0, HASH_SIZE);
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "bootloader incorrect hash length");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_1_hmac, hash_bootloader, nist_cavs_1_hmac_len,
                                          "bootloader hmac incorrect");

    printf("Test Vector NIST CAVS #1 HMAC: ");
    for (size_t index = 0; index < nist_cavs_1_hmac_len; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #2 */
    key_buffer.size = nist_cavs_2_key_len;
    key_buffer.size_max = nist_cavs_2_key_len;
    key_buffer.ptr = nist_cavs_2_key;

    input_buffer.size = nist_cavs_2_msg_len;
    input_buffer.size_max = nist_cavs_2_msg_len;
    input_buffer.ptr = nist_cavs_2_msg;

    memset(hash_bootloader, 0, HASH_SIZE);
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "bootloader incorrect hash length");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_2_hmac, hash_bootloader, nist_cavs_2_hmac_len,
                                          "bootloader hmac incorrect");

    printf("Test Vector NIST CAVS #2 HMAC: ");
    for (size_t index = 0; index < nist_cavs_2_hmac_len; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #3 */
    key_buffer.size = nist_cavs_3_key_len;
    key_buffer.size_max = nist_cavs_3_key_len;
    key_buffer.ptr = nist_cavs_3_key;

    input_buffer.size = nist_cavs_3_msg_len;
    input_buffer.size_max = nist_cavs_3_msg_len;
    input_buffer.ptr = nist_cavs_3_msg;

    memset(hash_bootloader, 0, HASH_SIZE);
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "bootloader incorrect hash length");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_3_hmac, hash_bootloader, nist_cavs_3_hmac_len,
                                          "bootloader hmac incorrect");

    printf("Test Vector NIST CAVS #3 HMAC: ");
    for (size_t index = 0; index < nist_cavs_3_hmac_len; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #4 */
    key_buffer.size = nist_cavs_4_key_len;
    key_buffer.size_max = nist_cavs_4_key_len;
    key_buffer.ptr = nist_cavs_4_key;

    input_buffer.size = nist_cavs_4_msg_len;
    input_buffer.size_max = nist_cavs_4_msg_len;
    input_buffer.ptr = nist_cavs_4_msg;

    memset(hash_bootloader, 0, HASH_SIZE);
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "bootloader incorrect hash length");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_4_hmac, hash_bootloader, nist_cavs_4_hmac_len,
                                          "bootloader hmac incorrect");

    printf("Test Vector NIST CAVS #4 HMAC: ");
    for (size_t index = 0; index < nist_cavs_4_hmac_len; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #5 */
    key_buffer.size = nist_cavs_5_key_len;
    key_buffer.size_max = nist_cavs_5_key_len;
    key_buffer.ptr = nist_cavs_5_key;

    input_buffer.size = nist_cavs_5_msg_len;
    input_buffer.size_max = nist_cavs_5_msg_len;
    input_buffer.ptr = nist_cavs_5_msg;

    memset(hash_bootloader, 0, HASH_SIZE);
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "bootloader incorrect hash length");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_5_hmac, hash_bootloader, nist_cavs_5_hmac_len,
                                          "bootloader hmac incorrect");

    printf("Test Vector NIST CAVS #5 HMAC: ");
    for (size_t index = 0; index < nist_cavs_5_hmac_len; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    /* Generic HMAC-SHA-256 Test Vector NIST CAVS #6 */
    key_buffer.size = nist_cavs_6_key_len;
    key_buffer.size_max = nist_cavs_6_key_len;
    key_buffer.ptr = nist_cavs_6_key;

    input_buffer.size = nist_cavs_6_msg_len;
    input_buffer.size_max = nist_cavs_6_msg_len;
    input_buffer.ptr = nist_cavs_6_msg;

    memset(hash_bootloader, 0, HASH_SIZE);
    result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "bootloader incorrect hash length");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nist_cavs_6_hmac, hash_bootloader, nist_cavs_6_hmac_len,
                                          "bootloader hmac incorrect");

    printf("Test Vector NIST CAVS #6 HMAC: ");
    for (size_t index = 0; index < nist_cavs_6_hmac_len; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    return CaseNext;
}

static control_t test_random_vector(const size_t call_count)
{
    printf("compare mbedtls hmac with bootloader hmac\r\n");

    size_t actual = 0;
    int retval = -1;

    /* generate random key and data */
    retval = mbedtls_hardware_poll(NULL, key_array, KEY_SIZE, &actual);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "wrong return value");
    TEST_ASSERT_EQUAL_INT_MESSAGE(KEY_SIZE, actual, "not enough entropy");

    retval = mbedtls_hardware_poll(NULL, data_array, DATA_SIZE, &actual);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "wrong return value");
    TEST_ASSERT_EQUAL_INT_MESSAGE(DATA_SIZE, actual, "not enough entropy");

    /* calculate hmac using mbedtls */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    TEST_ASSERT_NOT_NULL_MESSAGE(md_info, "invalid message digest struct");

    retval = mbedtls_md_hmac(md_info, key_array, KEY_SIZE, data_array, DATA_SIZE, hash_mbedtls);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, retval, "wrong return value");

    printf("%d: ", HASH_SIZE);
    for (size_t index = 0; index < HASH_SIZE; index++) {
        printf("%02X", hash_mbedtls[index]);
    }
    printf("\r\n");

    /* calculate hmac using bootloader */
    arm_uc_buffer_t key_buffer = { 0 };
    key_buffer.size = KEY_SIZE;
    key_buffer.size_max = KEY_SIZE;
    key_buffer.ptr = key_array;

    arm_uc_buffer_t input_buffer = { 0 };
    input_buffer.size = DATA_SIZE;
    input_buffer.size_max = DATA_SIZE;
    input_buffer.ptr = data_array;

    arm_uc_buffer_t output_buffer = { 0 };
    output_buffer.size = 0;
    output_buffer.size_max = HASH_SIZE;
    output_buffer.ptr = hash_bootloader;

    arm_uc_error_t result = ARM_UC_cryptoHMACSHA256(&key_buffer, &input_buffer, &output_buffer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ERR_NONE, result.code, "bootloader hmac failed");
    TEST_ASSERT_EQUAL_INT_MESSAGE(HASH_SIZE, output_buffer.size, "incorrect hash length");

    printf("%" PRIu32 ": ", output_buffer.size);
    for (size_t index = 0; index < output_buffer.size; index++) {
        printf("%02X", output_buffer.ptr[index]);
    }
    printf("\r\n");

    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(hash_mbedtls, hash_bootloader, HASH_SIZE, "bootloader hmac incorrect");


    return CaseNext;
}

utest::v1::status_t greentea_setup(const size_t number_of_cases)
{
    GREENTEA_SETUP(10 * 60, "default_auto");
    return greentea_test_setup_handler(number_of_cases);
}

Case cases[] = {
    Case("hmac sha256 unit", test_unit),
    Case("hmac sha256 NIST vectors", test_nist_vectors),
    Case("hmac sha256 random vector", test_random_vector),
};

Specification specification(greentea_setup, cases);

int main()
{
    return !Harness::run(specification);
}

#endif // !DEVICE_TRNG
