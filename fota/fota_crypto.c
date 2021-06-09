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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_crypto.h"
#include "fota/fota_status.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_nvm.h"
#include "fota_device_key.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ccm.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_RAW_PUBLIC_KEY_FORMAT) && defined(MBEDTLS_USE_TINYCRYPT)
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dsa.h"
#include "fota/fota_nvm.h"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_RAW_PUBLIC_KEY_FORMAT) && defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_X509_PUBLIC_KEY_FORMAT)
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509.h"
#endif
#include "mbedtls/pk.h"

#if defined(REMOVE_MBEDTLS_SSL_CONF_RNG)
#undef MBEDTLS_SSL_CONF_RNG
#endif

#if defined(MBEDTLS_SSL_CONF_RNG)
#include "shared_rng.h"
#endif

#include <stdlib.h>

#if !defined(MBEDTLS_SSL_CONF_RNG)
static bool random_initialized = false;
static mbedtls_entropy_context entropy_ctx;
#endif // !defined(MBEDTLS_SSL_CONF_RNG)

typedef struct fota_hash_context_s {
    mbedtls_sha256_context sha256_ctx;
} fota_hash_context_t;

typedef struct fota_encrypt_context_s {
    mbedtls_ccm_context ccm_ctx;
    uint64_t iv;
} fota_encrypt_context_t;

#define FOTA_TRACE_TLS_ERR(err) FOTA_TRACE_DEBUG("mbedTLS error %d", err)

#define FOTA_DERIVE_KEY_BITS 128

#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)
#define INITIAL_IV_VALUE 1
#else
#define INITIAL_IV_VALUE 0
#endif

#if !defined(FOTA_USE_EXTERNAL_SECRET_DERIVATION_STRING)
// Key derivation according to NIST Special Publication 800-108
// Using KDF in Counter Mode
// For i = 1 to n, do
// K(i) := PRF (KI, [i]2 || Label || 0x00 || Context || [L]2)
// We have only one iteration here, key size is 128 bits

// Building the input :
// 01 - i
// FOTA - Label
// 00 - separator
// ranadom value - Context
// [L]2 - key lenght
const unsigned char* fota_get_derivation_string(void)
{
#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)
    static const unsigned char derivation_string[FOTA_ENCRYPT_KEY_SIZE] = 
        "\x01" "FOTA" "\x00\x56\x3b\xe9\x8a\x94\xfd\x0d\xc0\x65\x80";
    return derivation_string;
#else
    return (const unsigned char*)"01FOTA00563be98a94fd0dc0651c0a80";
#endif
}
#endif

static int derive_key(uint8_t *key)
{
    uint8_t key_buf_hmac[FOTA_CRYPTO_HASH_SIZE];

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *) key, FOTA_ENCRYPT_KEY_SIZE,
                        fota_get_derivation_string(), 0x10, key_buf_hmac) == 0) {
        fota_fi_memcpy(key, key_buf_hmac, FOTA_ENCRYPT_KEY_SIZE);
        return FOTA_STATUS_SUCCESS;
    }

    return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
}

int fota_encrypt_decrypt_start(fota_encrypt_context_t **ctx, const uint8_t *key, uint32_t key_size)
{
    FOTA_DBG_ASSERT(ctx);
    int ret;

    *ctx = NULL;

    const uint8_t *key_to_use = key;

#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_DEVICE_KEY)
    uint8_t derived_key[key_size];
    fota_fi_memcpy(derived_key, key_to_use, key_size);
    ret = derive_key(derived_key);
    if (ret) {
        return ret;
    }
    key_to_use = derived_key;
#endif

    fota_encrypt_context_t *enc_ctx = (fota_encrypt_context_t *) malloc(sizeof(fota_encrypt_context_t));
    if (!enc_ctx) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    mbedtls_ccm_init(&enc_ctx->ccm_ctx);
    enc_ctx->iv = INITIAL_IV_VALUE;

    ret = mbedtls_ccm_setkey(&enc_ctx->ccm_ctx, MBEDTLS_CIPHER_ID_AES, key_to_use, FOTA_DERIVE_KEY_BITS);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        mbedtls_ccm_free(&enc_ctx->ccm_ctx);
        free(enc_ctx);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    *ctx = enc_ctx;

    return FOTA_STATUS_SUCCESS;
}

void fota_encryption_stream_reset(fota_encrypt_context_t *ctx)
{
    FOTA_DBG_ASSERT(ctx);
    ctx->iv = INITIAL_IV_VALUE;

}

void fota_encryption_iv_increment(fota_encrypt_context_t *ctx)
{
    FOTA_DBG_ASSERT(ctx);
    ctx->iv++;
}

int fota_encrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *tag)
{
    FOTA_DBG_ASSERT(ctx);
    FOTA_DBG_ASSERT(in_buf);
    FOTA_DBG_ASSERT(out_buf);
    FOTA_DBG_ASSERT(tag);

    int ret;
    volatile int flow_control = 0;
    uint64_t le_iv = FOTA_UINT64_TO_LE(ctx->iv);

    ret = mbedtls_ccm_encrypt_and_tag(
              &ctx->ccm_ctx, buf_size,
              (const unsigned char *) &le_iv, sizeof(ctx->iv),
              NULL, 0,
              in_buf, out_buf,
              tag, FOTA_ENCRYPT_TAG_SIZE);
    flow_control++;
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    flow_control++;
    fota_encryption_iv_increment(ctx);
    return (2 == flow_control) ? FOTA_STATUS_SUCCESS : FOTA_STATUS_INTERNAL_ERROR;
}

int fota_decrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *tag)
{
    FOTA_DBG_ASSERT(ctx);
    FOTA_DBG_ASSERT(in_buf);
    FOTA_DBG_ASSERT(out_buf);
    FOTA_DBG_ASSERT(tag);

    int ret;
    uint64_t le_iv = FOTA_UINT64_TO_LE(ctx->iv);

    ret = mbedtls_ccm_auth_decrypt(
              &ctx->ccm_ctx, buf_size,
              (const unsigned char *) &le_iv, sizeof(ctx->iv),
              NULL, 0,
              in_buf, out_buf,
              tag, FOTA_ENCRYPT_TAG_SIZE);

    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    fota_encryption_iv_increment(ctx);

    return FOTA_STATUS_SUCCESS;
}

int fota_encrypt_finalize(fota_encrypt_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    if (*ctx) {
        mbedtls_ccm_free(&(*ctx)->ccm_ctx);
        free(*ctx);
        *ctx = NULL;
    }

    return FOTA_STATUS_SUCCESS;
}

#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)

static int encrypt_decrypt_fw_key_start(fota_encrypt_context_t **ctx)
{
    int ret;
    uint8_t dev_key[FOTA_ENCRYPT_KEY_SIZE] = {0};

    // init CCM contex with key derived from device key

    ret = fota_get_device_key_128bit(dev_key, FOTA_ENCRYPT_KEY_SIZE);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to encrypt key. ret %d", ret);
        return ret;
    }

    ret = derive_key(dev_key);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to derive key. ret %d", ret);
        goto fail;
    }

    ret = fota_encrypt_decrypt_start(ctx, dev_key, sizeof(dev_key));
    if (ret) {
        FOTA_TRACE_ERROR("Failed to start encryption engine. ret %d", ret);
        goto fail;
    }

fail:
    // Clear key's buffer from memory due to security reasons
    memset(dev_key, 0, FOTA_ENCRYPT_KEY_SIZE);
    return ret;
}

/*
 * Encrypt fw key.
 *
 * \param[in]  plain_key             Key buffer to encrypt
 * \param[out] encrypted_fw_key      Buffer holding the encrypted data
 * \param[out] encrypted_fw_key_tag  Buffer holding the encrypted tag
 * \param[out] encrypted_fw_key_iv   Buffer holding the encrypted buffer
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_encrypt_fw_key(uint8_t plain_key[FOTA_ENCRYPT_KEY_SIZE],
                        uint8_t encrypted_fw_key[FOTA_ENCRYPT_KEY_SIZE],
                        uint8_t encrypted_fw_key_tag[FOTA_ENCRYPT_TAG_SIZE],
                        uint64_t *encrypted_fw_key_iv)
{
    FOTA_DBG_ASSERT(encrypted_fw_key_iv);
    int ret;
    fota_encrypt_context_t *temp_ctx = NULL;

    // encrypt gen_key buffer using device key and store it in the header

    ret = encrypt_decrypt_fw_key_start(&temp_ctx);
    if (ret) {
        return ret;
    }

    // generate random iv
    ret = fota_gen_random((uint8_t*)encrypted_fw_key_iv, sizeof(uint64_t));
    if (ret) {
        FOTA_TRACE_ERROR("Unable to generate random data. ret %d", ret);
        return ret;
    }

    // set ccm to use generated iv
    temp_ctx->iv = *encrypted_fw_key_iv;

    ret = fota_encrypt_data(temp_ctx,
                            plain_key, FOTA_ENCRYPT_KEY_SIZE,
                            encrypted_fw_key, encrypted_fw_key_tag);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to encrypt buffer. ret %d", ret);
        goto fail;
    }

fail:
    fota_encrypt_finalize(&temp_ctx);
    return ret;
}

/*
 * Decrypt fw key.
 *
 * \param[out] plain_key             Key buffer to encrypt
 * \param[in]  encrypted_fw_key      Buffer holding the encrypted data
 * \param[in]  encrypted_fw_key_tag  Buffer holding the encrypted tag
 * \param[in]  encrypted_fw_key_iv   Buffer holding the encrypted buffer
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_decrypt_fw_key(uint8_t plain_key[FOTA_ENCRYPT_KEY_SIZE],
                        uint8_t encrypted_fw_key[FOTA_ENCRYPT_KEY_SIZE],
                        uint8_t encrypted_fw_key_tag[FOTA_ENCRYPT_TAG_SIZE],
                        uint64_t encrypted_fw_key_iv)
{
    int ret;
    fota_encrypt_context_t *temp_ctx = NULL;

    // decrypt encrypted_fw_key buffer using key derived from device key

    ret = encrypt_decrypt_fw_key_start(&temp_ctx);
    if (ret) {
        return ret;
    }

    // set ccm to use generated iv
    temp_ctx->iv = encrypted_fw_key_iv;

    ret = fota_decrypt_data(temp_ctx, encrypted_fw_key, FOTA_ENCRYPT_KEY_SIZE,
                                      plain_key, encrypted_fw_key_tag);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to encrypt buffer. ret %d", ret);
        goto fail;
    }

fail:
    fota_encrypt_finalize(&temp_ctx);
    return ret;
}
#endif // (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)

int fota_hash_start(fota_hash_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    int ret;
    *ctx = NULL;

    fota_hash_context_t *hash_ctx = (fota_hash_context_t *) malloc(sizeof(fota_hash_context_t));
    if (!hash_ctx) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    mbedtls_sha256_init(&hash_ctx->sha256_ctx);

    ret = mbedtls_sha256_starts_ret(&hash_ctx->sha256_ctx, 0);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    *ctx = hash_ctx;
    return FOTA_STATUS_SUCCESS;
}

int fota_hash_update(fota_hash_context_t *ctx, const uint8_t *buf, uint32_t buf_size)
{
    FOTA_DBG_ASSERT(ctx);
    int ret = mbedtls_sha256_update_ret(&ctx->sha256_ctx, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_hash_result(fota_hash_context_t *ctx, uint8_t *hash_buf)
{
    FOTA_DBG_ASSERT(ctx);
    int ret = mbedtls_sha256_finish_ret(&ctx->sha256_ctx, hash_buf);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

void fota_hash_finish(fota_hash_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    if (*ctx) {
        mbedtls_sha256_free(&(*ctx)->sha256_ctx);
        free(*ctx);
        *ctx = NULL;
    }
}

int fota_random_init(const uint8_t *seed, uint32_t seed_size)
{
#if !defined(MBEDTLS_SSL_CONF_RNG)
    if (!random_initialized) {
        mbedtls_entropy_init(&entropy_ctx);
        random_initialized = true;
    }
#endif // !defined(MBEDTLS_SSL_CONF_RNG)
    return FOTA_STATUS_SUCCESS;
}

#if !defined(MBEDTLS_SSL_CONF_RNG)
int fota_gen_random(uint8_t *buf, uint32_t buf_size)
{
    FOTA_DBG_ASSERT(random_initialized);

    int ret = mbedtls_entropy_func(&entropy_ctx, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}
#else
int fota_gen_random(uint8_t *buf, uint32_t buf_size)
{
    int ret = global_rng(NULL, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}
#endif // !defined(MBEDTLS_SSL_CONF_RNG)

int fota_random_deinit(void)
{
#if !defined(MBEDTLS_SSL_CONF_RNG)
    if (random_initialized) {
        mbedtls_entropy_free(&entropy_ctx);
        random_initialized = false;
    }
#endif // !defined(MBEDTLS_SSL_CONF_RNG)    
    return FOTA_STATUS_SUCCESS;
}

#if FOTA_FI_MITIGATION_ENABLE
int fota_fi_memcmp(const uint8_t *ptr1, const uint8_t *ptr2, size_t num, volatile size_t *loop_check)
{
    volatile int is_diff = 0;
    volatile size_t pos;
    uint32_t start_pos = mbedtls_platform_random_in_range(num);

    for (*loop_check = 0; *loop_check < num; (*loop_check)++) {
        pos = (*loop_check + start_pos) % num;
        is_diff |= (ptr1[pos] ^ ptr2[pos]);
    }
    return is_diff;
}
#endif // #if FOTA_FI_MITIGATION_ENABLE

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_RAW_PUBLIC_KEY_FORMAT) && defined(MBEDTLS_USE_TINYCRYPT)
int fota_verify_signature_prehashed(
    const uint8_t *data_digest,
    const uint8_t *sig, size_t sig_len
)
{
    volatile int flow_control = 0;
    uint8_t public_key[FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE];
    int ret = fota_nvm_get_update_public_key(public_key);

    if (ret) {
        FOTA_TRACE_ERROR("Failed to get public key");
        return ret;
    }
    flow_control++;
    ret = uECC_verify(
              public_key + 1, // +1 for dropping the compression byte
              data_digest, FOTA_CRYPTO_HASH_SIZE,
              sig
          );
    flow_control++;
    FOTA_FI_SAFE_COND(ret == UECC_SUCCESS, FOTA_STATUS_MANIFEST_SIGNATURE_INVALID, "Failed to uECC_verify");
    flow_control++;
    FOTA_TRACE_DEBUG("uECC_verify passed");

    return (3 == flow_control) ? FOTA_STATUS_SUCCESS : FOTA_STATUS_INTERNAL_ERROR;

fail:

    return ret;
}
#endif

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_RAW_PUBLIC_KEY_FORMAT) && defined(MBEDTLS_ECDSA_C)
int fota_verify_signature_prehashed(
    const uint8_t *data_digest,
    const uint8_t *sig, size_t sig_len
)
{
    volatile int flow_control = 0;
    uint8_t public_key[FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE];
    int ret = FOTA_STATUS_INTERNAL_ERROR;
    int tmp_ret = fota_nvm_get_update_public_key(public_key);
    if (tmp_ret) {
        FOTA_TRACE_ERROR("Failed to get public key %d", tmp_ret);
        return tmp_ret;
    }

    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_point Q;
    size_t curve_bytes;
    mbedtls_mpi r, s;

    flow_control++;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_init(&ecp_group);

    tmp_ret = mbedtls_ecp_group_load(
                  &ecp_group,
                  MBEDTLS_ECP_DP_SECP256R1);
    FOTA_TRACE_DEBUG("mbedtls_ecp_group_load returned %d", tmp_ret);

    if (tmp_ret) {
        FOTA_TRACE_ERROR("Failed to load ecp group");
        ret = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto fail;
    }

    curve_bytes = FOTA_IMAGE_RAW_SIGNATURE_SIZE / 2;

    FOTA_DBG_ASSERT(sig_len == 2 * curve_bytes);

    tmp_ret = mbedtls_mpi_read_binary(&r,
                                      sig,
                                      curve_bytes);
    FOTA_TRACE_DEBUG("mbedtls_mpi_read_binary r returned %d", tmp_ret);

    if (tmp_ret) {
        FOTA_TRACE_ERROR("mbedtls_mpi_read_binary");
        ret = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto fail;
    }

    tmp_ret = mbedtls_mpi_read_binary(&s,
                                      sig + curve_bytes,
                                      curve_bytes);
    FOTA_TRACE_DEBUG("mbedtls_mpi_read_binary s returned %d", tmp_ret);

    if (tmp_ret) {
        FOTA_TRACE_ERROR("mbedtls_mpi_read_binary");
        ret = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto fail;
    }

    tmp_ret = mbedtls_ecp_point_read_binary(&ecp_group,
                                            &Q,
                                            public_key,
                                            FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE);

    FOTA_TRACE_DEBUG("mbedtls_ecp_point_read_binary returned %d", tmp_ret);

    if (tmp_ret) {
        FOTA_TRACE_ERROR("Failed to mbedtls_ecp_point_read_binary public key");
        ret = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto fail;
    }
    flow_control++;
    tmp_ret = mbedtls_ecdsa_verify(
                  &ecp_group,
                  data_digest, FOTA_CRYPTO_HASH_SIZE,
                  &Q,
                  &r, &s
              );
    flow_control++;
    FOTA_FI_SAFE_COND(!tmp_ret, FOTA_STATUS_MANIFEST_SIGNATURE_INVALID, "Failed to verify signature");
    flow_control++;

    FOTA_TRACE_DEBUG("mbedtls_ecdsa_verify passed");

    ret = (4 == flow_control) ? FOTA_STATUS_SUCCESS : FOTA_STATUS_INTERNAL_ERROR;

fail:

    mbedtls_ecp_group_free(&ecp_group);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);

    return ret;

}
#endif

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_X509_PUBLIC_KEY_FORMAT)
int fota_verify_signature_prehashed(
    const uint8_t *data_digest,
    const uint8_t *sig, size_t sig_len
)
{
    int ret;
    volatile int flow_control = 0;
    int fota_status = FOTA_STATUS_INTERNAL_ERROR;
    uint8_t *update_crt_data;
    mbedtls_pk_context *pk_ctx_ptr = NULL;
    size_t update_crt_size;
    mbedtls_x509_crt crt;
#if defined(MBEDTLS_X509_ON_DEMAND_PARSING)
    mbedtls_pk_context pk_ctx;
#endif
    flow_control++;
    update_crt_data = (uint8_t *)malloc(FOTA_CERT_MAX_SIZE);
    if (!update_crt_data) {
        FOTA_TRACE_ERROR("Failed to allocate storage for update certificate");
        fota_status = FOTA_STATUS_OUT_OF_MEMORY;
        goto fail;
    }

    ret = fota_nvm_get_update_certificate(
              update_crt_data, FOTA_CERT_MAX_SIZE,
              &update_crt_size
          );
    if (ret) {
        fota_status = ret;
        FOTA_TRACE_ERROR("Failed to get update certificate %d", ret);
        goto fail;
    }

    mbedtls_x509_crt_init(&crt);

/*mbedtls_x509_crt_parse_der_nocopy not supported for mbedtls 2.16.0 and lower versions,
 use older version of x509 cert parse function */
#if  (MBEDTLS_VERSION_NUMBER < 0x02110000)
    ret = mbedtls_x509_crt_parse_der(
#else
    ret = mbedtls_x509_crt_parse_der_nocopy(
#endif
              &crt,
              update_crt_data, update_crt_size
          );
    if (ret) {
        FOTA_TRACE_ERROR("Failed to parse update certificate %d", ret);
        if (ret == MBEDTLS_ERR_X509_ALLOC_FAILED) {
            fota_status = FOTA_STATUS_OUT_OF_MEMORY;
        } else {
            fota_status = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        }
        goto fail;
    }

    // supporting both crypto lib api
#if defined(MBEDTLS_X509_ON_DEMAND_PARSING)
    pk_ctx_ptr = &pk_ctx;
    mbedtls_pk_init(pk_ctx_ptr);
    ret = mbedtls_x509_crt_get_pk(&crt, pk_ctx_ptr);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to extract public key from certificate %d", ret);
        fota_status = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto fail;
    }
#else
    pk_ctx_ptr = &crt.pk;
#endif
    flow_control++;
    ret = mbedtls_pk_verify(
              pk_ctx_ptr, MBEDTLS_MD_SHA256,
              data_digest, FOTA_CRYPTO_HASH_SIZE,
              sig, sig_len
          );
    flow_control++;
    // todo FI check
    if (ret) {
        FOTA_TRACE_ERROR("Manifest signature verification failed (%d)", ret);
        fota_status = FOTA_STATUS_MANIFEST_SIGNATURE_INVALID;
        goto fail;
    }
    flow_control++;
    fota_status = (4 == flow_control) ? FOTA_STATUS_SUCCESS : FOTA_STATUS_INTERNAL_ERROR;

fail:

#ifdef MBEDTLS_X509_ON_DEMAND_PARSING
    mbedtls_pk_free(pk_ctx_ptr);
#endif

    mbedtls_x509_crt_free(&crt);
    free(update_crt_data);
    return fota_status;
}
#endif // #if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_X509_PUBLIC_KEY_FORMAT)

int fota_verify_signature(
    const uint8_t *signed_data, size_t signed_data_size,
    const uint8_t *sig, size_t sig_len
)
{
    volatile int flow_control = 0;
    uint8_t digest[FOTA_CRYPTO_HASH_SIZE] = {0};
    mbedtls_sha256_context sha256_ctx = {0};
    mbedtls_sha256_init(&sha256_ctx);

    int ret = FOTA_STATUS_INTERNAL_ERROR;
    int status;

    status = mbedtls_sha256_starts_ret(&sha256_ctx, 0);
    if (status) {
        goto fail;
    }
    flow_control++;
    status = mbedtls_sha256_update_ret(&sha256_ctx, signed_data, signed_data_size);
    if (status) {
        mbedtls_sha256_free(&sha256_ctx);
        goto fail;
    }
    flow_control++;
    status = mbedtls_sha256_finish_ret(&sha256_ctx, digest);
    mbedtls_sha256_free(&sha256_ctx);
    if (status) {
        goto fail;
    }
    flow_control++;
    ret = fota_verify_signature_prehashed(
              digest,
              sig, sig_len
          );
    flow_control++;
    FOTA_FI_SAFE_COND(
        ret == FOTA_STATUS_SUCCESS,
        ret,
        "Manifest signature verification failed"
    );
    flow_control++;
    ret = (5 == flow_control) ? FOTA_STATUS_SUCCESS : FOTA_STATUS_INTERNAL_ERROR;

fail:
    return ret;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
