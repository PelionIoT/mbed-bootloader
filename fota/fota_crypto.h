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

#ifndef __FOTA_CRYPTO_H_
#define __FOTA_CRYPTO_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_crypto_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fota_encrypt_context_s fota_encrypt_context_t;

int fota_encrypt_decrypt_start(fota_encrypt_context_t **ctx, const uint8_t *key, uint32_t key_size);

// reset stream
// reset iv and buffering states
void fota_encryption_stream_reset(fota_encrypt_context_t *ctx);

void fota_encryption_iv_increment(fota_encrypt_context_t *ctx);

int fota_encrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *tag);
int fota_decrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *tag);
int fota_encrypt_finalize(fota_encrypt_context_t **ctx);

typedef struct fota_hash_context_s fota_hash_context_t;

int fota_hash_start(fota_hash_context_t **ctx);
int fota_hash_update(fota_hash_context_t *ctx, const uint8_t *buf, uint32_t buf_size);
int fota_hash_result(fota_hash_context_t *ctx, uint8_t *hash_buf);
void fota_hash_finish(fota_hash_context_t **ctx);

int fota_random_init(const uint8_t *seed, uint32_t seed_size);
int fota_gen_random(uint8_t *buf, uint32_t buf_size);
int fota_random_deinit(void);


#if FOTA_FI_MITIGATION_ENABLE

// TODO: check if should return volatile
int fota_fi_memcmp(const uint8_t *ptr1, const uint8_t *ptr2, size_t num, volatile size_t *loop_check);

#include "mbedtls/platform_util.h"
// This handles a a fault injection safe condition - desired condition tested 3 times with random delay between checks
// (to prevent power glitch attacks).
// In case of a bad case scenario, error message is displayed (if not null), variable ret (must exist) is filled with RET
// and we jump to label "fail", which must exist.
#define FOTA_FI_SAFE_COND(DESIRED_COND, RET, MSG, ...) \
do { \
    if (!(DESIRED_COND)) { \
        FOTA_TRACE_ERROR(MSG, ##__VA_ARGS__); \
        ret = RET; \
        goto fail; \
    } \
    mbedtls_platform_random_delay(); \
    if (!(DESIRED_COND)) { \
        FOTA_TRACE_ERROR(MSG, ##__VA_ARGS__); \
        ret = RET; \
        goto fail; \
    } \
} while (0)

// specific case, safe memcmp (desired condition is equal strings)
#define FOTA_FI_SAFE_MEMCMP(PTR1, PTR2, NUM, RET, MSG, ...) \
do { \
    size_t volatile loop_check; \
    FOTA_FI_SAFE_COND((!fota_fi_memcmp((PTR1), (PTR2), (NUM), &loop_check) && (loop_check == (NUM))), RET, MSG, ##__VA_ARGS__); \
} while (0)

static inline void* fota_fi_memcpy(void *dst, const void *src, size_t num)
{
    return mbedtls_platform_memcpy(dst, src, num);
}

static inline void* fota_fi_memset(void *ptr, int value, size_t num)
{
    return mbedtls_platform_memset(ptr, value, num);
}

#else // no FI support

// No FI mitigation, simple handling
#define FOTA_FI_SAFE_COND(DESIRED_COND, RET, MSG, ...) \
do { \
    if (!(DESIRED_COND)) { \
        FOTA_TRACE_ERROR(MSG, ##__VA_ARGS__); \
        ret = RET; \
        goto fail; \
    } \
} while (0)

// specific case, regular memcmp (desired condition is equal strings)
#define FOTA_FI_SAFE_MEMCMP(PTR1, PTR2, NUM, RET, MSG, ...) \
    FOTA_FI_SAFE_COND(!memcmp((PTR1), (PTR2), (NUM)), RET, MSG, ##__VA_ARGS__)

static inline int fota_fi_memcmp(const uint8_t *ptr1, const uint8_t *ptr2, size_t num, volatile size_t *loop_check)
{
    *loop_check = num;
    return memcmp(ptr1, ptr2, num);
}

static inline void* fota_fi_memcpy(void *dst, const void *src, size_t num)
{
    return memcpy(dst, src, num);
}

static inline void* fota_fi_memset(void *ptr, int value, size_t num)
{
    return memset(ptr, value, num);
}

#endif // #if FOTA_FI_MITIGATION_ENABLE

int fota_verify_signature(
    const uint8_t *signed_data, size_t signed_data_size,
    const uint8_t *sig, size_t sig_len
);

int fota_verify_signature_prehashed(
    const uint8_t *data_digest,
    const uint8_t *sig, size_t sig_len
);

#if (MBED_CLOUD_CLIENT_FOTA_KEY_DERIVATION == FOTA_ENCRYPT_KEY_ECB_DERIVATION || MBED_CLOUD_CLIENT_FOTA_KEY_DERIVATION == FOTA_ENCRYPT_KEY_HMAC_DERIVATION)
const unsigned char* fota_get_derivation_string(void);
#endif

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_CRYPTO_H_
