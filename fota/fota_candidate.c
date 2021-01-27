// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#include "fota/fota_candidate.h"
#include "fota/fota_status.h"
#include "fota/fota_block_device.h"
#include "fota/fota_crypto.h"
#include "fota/fota_nvm.h"
#include <stdlib.h>
#include <inttypes.h>

#define MIN_FRAG_SIZE 128

typedef struct {
    size_t bd_read_size;
    size_t bd_prog_size;
    size_t   curr_addr;
    size_t   data_start_addr;
    uint32_t effective_block_size;
    uint32_t block_checker_size;
    uint32_t frag_extra_bytes;
    size_t   bytes_completed;
    uint32_t install_alignment;
    uint8_t  *fragment_buf;

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_encrypt_context_t *enc_ctx;
#endif

    fota_header_info_t header_info;

} candidate_contex_t;

static fota_candidate_config_t fota_candidate_config = {
    .storage_start_addr     = 0,
    .storage_size           = 0,
};

static candidate_contex_t *ctx = NULL;

uint32_t fota_bd_physical_addr_to_logical_addr(uint32_t phys_addr);

void fota_candidate_set_config(fota_candidate_config_t *in_fota_candidate_config)
{
    FOTA_ASSERT(in_fota_candidate_config->storage_size);
    memcpy(&fota_candidate_config, in_fota_candidate_config, sizeof(fota_candidate_config_t));
}

const fota_candidate_config_t *fota_candidate_get_config(void)
{
    if (!fota_candidate_config.storage_size) {
        fota_candidate_config_t fota_candidate_init_config = {
            .storage_start_addr     = fota_bd_physical_addr_to_logical_addr(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR),
            .storage_size           = MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE,
        };
        fota_candidate_set_config(&fota_candidate_init_config);
    }
    return (const fota_candidate_config_t *) &fota_candidate_config;
}

int fota_candidate_read_candidate_ready_header(size_t *addr, uint32_t bd_read_size, uint32_t bd_prog_size,
                                               fota_candidate_ready_header_t *header)
{
    int ret = FOTA_STATUS_SUCCESS;
// Return success on non BL ready headers (let parse_header deal with it)
#if FOTA_HEADER_HAS_CANDIDATE_READY
    uint8_t read_buf[sizeof(fota_candidate_ready_header_t)];
    uint8_t *aligned_read_buf = read_buf;

    uint32_t chunk_size = FOTA_ALIGN_UP(sizeof(fota_candidate_ready_header_t), bd_read_size);

    if (chunk_size > sizeof(read_buf)) {
        // This is very unlikely to happen, as read size is usually 1.
        // So prefer the buffer to be allocated on stack, which is the likely case.
        aligned_read_buf = (uint8_t *) malloc(chunk_size);
        if (!aligned_read_buf) {
            FOTA_TRACE_ERROR("FOTA aligned_read_buf - allocation failed");
            return FOTA_STATUS_OUT_OF_MEMORY;
        }
    }
    ret = fota_bd_read(aligned_read_buf, *addr, chunk_size);
    if (ret) {
        ret = FOTA_STATUS_STORAGE_READ_FAILED;
        goto end;
    }

    memcpy(header, aligned_read_buf, sizeof(fota_candidate_ready_header_t));
    if (header->magic != FOTA_CANDIDATE_READY_MAGIC) {
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION < 3)
        // This code is practically available for testing only, as fota_candidate code is not called on legacy bootloaders.
        // In case of a legacy header, if we don't have magic, this probably means that the candidate ready header is
        // missing for the main component.
        FOTA_TRACE_DEBUG("Probably main component on a legacy device");
        strcpy(header->comp_name, FOTA_COMPONENT_MAIN_COMPONENT_NAME);
        ret = FOTA_STATUS_SUCCESS;
#else
        FOTA_TRACE_INFO("No image found on storage");
        ret = FOTA_STATUS_NOT_FOUND;
#endif
        goto end;
    }

    // Advance read address for next calls
    *addr += FOTA_ALIGN_UP(chunk_size, bd_prog_size);

end:
    if (chunk_size > sizeof(read_buf)) {
        free(aligned_read_buf);
    }
#endif
    return ret;
}

static void cleanup()
{
    if (!ctx) {
        return;
    }
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->enc_ctx) {
        fota_encrypt_finalize(&ctx->enc_ctx);
    }
#endif
    free(ctx->fragment_buf);
    free(ctx);
    ctx = 0;
}

int fota_candidate_read_header(size_t *addr, uint32_t bd_read_size, uint32_t bd_prog_size, fota_header_info_t *header)
{
    uint32_t header_size = (uint32_t) fota_get_header_size();
    uint32_t read_size = FOTA_ALIGN_UP(header_size, bd_read_size);

    uint8_t *header_buf = (uint8_t *) malloc(read_size);
    if (!header_buf) {
        FOTA_TRACE_ERROR("FOTA header - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    int ret = fota_bd_read(header_buf, *addr, read_size);
    *addr += FOTA_ALIGN_UP(header_size, bd_prog_size);

    if (ret) {
        goto end;
    }

    ret = fota_deserialize_header(header_buf, header_size, header);
    if (ret) {
        goto end;
    }

end:
    free(header_buf);
    return ret;
}

static int fota_candidate_extract_start(bool force_encrypt, const char *expected_comp_name,
                                        uint32_t install_alignment)
{
    int ret;
    uint32_t alloc_size, block_size;

    if (!ctx) {
        ctx = (candidate_contex_t *) calloc(1, sizeof(candidate_contex_t));
        if (!ctx) {
            FOTA_TRACE_ERROR("FOTA candidate_contex_t - allocation failed");
            return FOTA_STATUS_OUT_OF_MEMORY;
        }

        ret = fota_bd_get_read_size(&ctx->bd_read_size);
        if (ret) {
            FOTA_TRACE_ERROR("fota_bd_get_read_size error %d", ret);
            goto fail;
        }

        ret = fota_bd_get_program_size(&ctx->bd_prog_size);
        if (ret) {
            FOTA_TRACE_ERROR("fota_bd_get_program_size error %d", ret);
            goto fail;
        }

        ctx->curr_addr = fota_candidate_get_config()->storage_start_addr;

        fota_candidate_ready_header_t header;
        ret = fota_candidate_read_candidate_ready_header(&ctx->curr_addr, ctx->bd_read_size, ctx->bd_prog_size, &header);
        if (ret) {
            goto fail;
        }

#if FOTA_HEADER_HAS_CANDIDATE_READY
        if (strncmp(header.comp_name, expected_comp_name, strlen(expected_comp_name))) {
            FOTA_TRACE_ERROR("Unexpected component candidate found");
            ret = FOTA_STATUS_UNEXPECTED_COMPONENT;
            goto fail;
        }
#endif

        ret = fota_candidate_read_header(&ctx->curr_addr, ctx->bd_read_size, ctx->bd_prog_size, &ctx->header_info);
        if (ret) {
            FOTA_TRACE_ERROR("Header parsing failed. ret %d", ret);
            goto fail;
        }

        if (ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) {
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 0)
            FOTA_TRACE_ERROR("Encrypted candidate image - not supported");
            ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
            goto fail;
#endif
            FOTA_TRACE_INFO("Found an encrypted image at address 0x%zx", fota_candidate_get_config()->storage_start_addr);
        } else  {
            if (force_encrypt) {
                FOTA_TRACE_ERROR("Non-encrypted image found, but this is not allowed for this candidate type.");
                ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
                goto fail;
            }
            FOTA_TRACE_INFO("Found a non-encrypted image at address 0x%zx", fota_candidate_get_config()->storage_start_addr);
        }

        if (ctx->header_info.flags & (FOTA_HEADER_ENCRYPTED_FLAG | FOTA_HEADER_SUPPORT_RESUME_FLAG)) {
            block_size = ctx->header_info.block_size;
        } else {
            block_size = MIN_FRAG_SIZE;
        }
        block_size = FOTA_ALIGN_UP(block_size, ctx->bd_read_size);

        // Block checker can be different here and have different sizes:
        // Tag (8 bytes) in encrypted case, checksum (2 bytes) in non-encrypted case (with resume support).
        if (ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) {
            ctx->block_checker_size = FOTA_ENCRYPT_TAG_SIZE;
        } else if (ctx->header_info.flags & FOTA_HEADER_SUPPORT_RESUME_FLAG) {
            ctx->block_checker_size = sizeof(fota_candidate_block_checksum_t);
        } else {
            ctx->block_checker_size = 0;
        }
        ctx->effective_block_size = block_size - ctx->block_checker_size;

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        if (ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) {
            uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE] = {0};
            uint8_t zero_key[FOTA_ENCRYPT_KEY_SIZE] = {0};
            size_t volatile loop_check;

            ret = fota_nvm_fw_encryption_key_get(fw_key);
            if (ret) {
                FOTA_TRACE_ERROR("FW encryption key get failed. ret %d", ret);
                goto fail;
            }

            // safely check that read key is non zero
            FOTA_FI_SAFE_COND((fota_fi_memcmp(fw_key, zero_key, FOTA_ENCRYPT_KEY_SIZE, &loop_check)
                               && (loop_check == FOTA_ENCRYPT_KEY_SIZE)), FOTA_STATUS_INTERNAL_ERROR,
                              "Invalid encryption key read");

            ret = fota_encrypt_decrypt_start(&ctx->enc_ctx, fw_key, FOTA_ENCRYPT_KEY_SIZE);
            memset(fw_key, 0, sizeof(fw_key));
            if (ret) {
                FOTA_TRACE_ERROR("Decrypt start failed. ret %d", ret);
                goto fail;
            }

            ctx->curr_addr = FOTA_ALIGN_UP(ctx->curr_addr, ctx->bd_prog_size);
        }
#endif

        ctx->data_start_addr = ctx->curr_addr;
    } // !ctx

    ctx->curr_addr = ctx->data_start_addr;
    ctx->bytes_completed = 0;
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) {
        fota_encryption_stream_reset(ctx->enc_ctx);
    }
#endif

    // Install alignment of zero is just like an alignment of 1 (i.e. no limitation)
    ctx->install_alignment = install_alignment ? install_alignment : 1;
    free(ctx->fragment_buf);

    alloc_size = ctx->effective_block_size + ctx->block_checker_size;

    // In case we are not aligned to installer requirements, need an extra
    if (ctx->effective_block_size % ctx->install_alignment) {
        alloc_size += ctx->install_alignment;
    }

    ctx->fragment_buf = (uint8_t *) malloc(alloc_size);
    if (!ctx->fragment_buf) {
        FOTA_TRACE_ERROR("FOTA ctx->fragment_buf - allocation failed");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto fail;
    }

    return FOTA_STATUS_SUCCESS;

fail:
    cleanup();
    return ret;
}

static int fota_candidate_extract_fragment(uint8_t **buf, size_t *actual_size, bool *ignore)
{
    size_t read_size;
    int ret;

    FOTA_DBG_ASSERT(ctx);


    // Move extra bytes from last time from end to beginning of buffer
    if (!*ignore) {
        memcpy(ctx->fragment_buf, ctx->fragment_buf + *actual_size, ctx->frag_extra_bytes);
    }
    *buf = ctx->fragment_buf + ctx->frag_extra_bytes;

    *ignore = false;

    *actual_size = MIN(ctx->header_info.fw_size - ctx->bytes_completed, ctx->effective_block_size);
    if (!*actual_size) {
        return FOTA_STATUS_SUCCESS;
    }

    read_size = FOTA_ALIGN_UP(ctx->block_checker_size + *actual_size, ctx->bd_read_size);

    if (ctx->curr_addr + read_size >
            fota_candidate_get_config()->storage_start_addr + fota_candidate_get_config()->storage_size) {
        FOTA_TRACE_ERROR("Storage end address exceeded");
        return FOTA_STATUS_STORAGE_READ_FAILED;
    }

    ret = fota_bd_read(*buf, ctx->curr_addr, read_size);
    if (ret) {
        FOTA_TRACE_ERROR("storage read failed, ret %d", ret);
        return ret;
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) {
        uint8_t *tag = *buf;
        *buf += FOTA_ENCRYPT_TAG_SIZE;
        ret = fota_decrypt_data(ctx->enc_ctx, *buf, *actual_size, *buf, tag);
        if (ret) {
            if (ctx->header_info.flags & FOTA_HEADER_SUPPORT_RESUME_FLAG) {
                FOTA_TRACE_DEBUG("Bad block ignored");
                *ignore = true;
            } else {
                FOTA_TRACE_ERROR("decrypt data failed, ret %d", ret);
                return ret;
            }
        }
    }
#endif

    if (!(ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) &&
            (ctx->header_info.flags & FOTA_HEADER_SUPPORT_RESUME_FLAG)) {
        fota_candidate_block_checksum_t read_checksum = *(fota_candidate_block_checksum_t *) *buf;
        *buf += sizeof(fota_candidate_block_checksum_t);
        fota_candidate_block_checksum_t calc_checksum = 0;
        for (uint32_t i = 0; i < *actual_size; i++) {
            calc_checksum += (*buf)[i];
        }
        if (calc_checksum != read_checksum) {
            FOTA_TRACE_DEBUG("Bad block ignored");
            *ignore = true;
        }
    }

    ctx->curr_addr += read_size;

    if (*ignore) {
        return FOTA_STATUS_SUCCESS;
    }

    ctx->bytes_completed += *actual_size;

    if (*actual_size % ctx->install_alignment || ctx->frag_extra_bytes) {
        // Not aligned, need to gather read data (without checker) and extra bytes from previous time
        memmove(*buf - ctx->block_checker_size, *buf, *actual_size);
        *buf = ctx->fragment_buf;
        *actual_size += ctx->frag_extra_bytes;
        if (*actual_size >= ctx->effective_block_size) {
            ctx->frag_extra_bytes = *actual_size % ctx->install_alignment;
            *actual_size -= ctx->frag_extra_bytes;
        }
        *actual_size = FOTA_ALIGN_UP(*actual_size, ctx->install_alignment);
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_candidate_iterate_image(uint8_t validate, bool force_encrypt, const char *expected_comp_name,
                                 uint32_t install_alignment, fota_candidate_iterate_handler_t handler)
{
    int ret;
    fota_candidate_iterate_callback_info cb_info;
    size_t actual_size = 0;
    uint8_t *buf = NULL;
    fota_hash_context_t *hash_ctx = NULL;
    bool ignore = false;

    FOTA_ASSERT(handler);

    ret = fota_candidate_extract_start(force_encrypt, expected_comp_name, 0);
    if (ret) {
        goto fail;
    }

    if (validate != FOTA_CANDIDATE_SKIP_VALIDATION) {
        FOTA_TRACE_INFO("Validating image...");
        uint8_t hash_output[FOTA_CRYPTO_HASH_SIZE];

        ret = fota_hash_start(&hash_ctx);
        if (ret) {
            goto fail;
        }
        do {
            ret = fota_candidate_extract_fragment(&buf, &actual_size, &ignore);
            if (ret) {
                goto fail;
            }
            if (ignore) {
                continue;
            }

            ret = fota_hash_update(hash_ctx, buf, actual_size);
            if (ret) {
                goto fail;
            }

        } while (actual_size);

        ret = fota_hash_result(hash_ctx, hash_output);
        if (ret) {
            goto fail;
        }

        fota_hash_finish(&hash_ctx);

#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
        int sig_verify_status = fota_verify_signature_prehashed(
                                    hash_output,
                                    ctx->header_info.signature, FOTA_IMAGE_RAW_SIGNATURE_SIZE
                                );
        FOTA_FI_SAFE_COND(
            (sig_verify_status == FOTA_STATUS_SUCCESS),
            (sig_verify_status == FOTA_STATUS_MANIFEST_SIGNATURE_INVALID) ? FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED : ret,
            "Candidate image is not authentic"
        );
#else
        FOTA_FI_SAFE_MEMCMP(hash_output, ctx->header_info.digest, FOTA_CRYPTO_HASH_SIZE,
                            FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
                            "Hash mismatch - corrupted candidate");
#endif
        FOTA_TRACE_INFO("Image is valid.");
    }

    // Start iteration phase

    actual_size = 0;
    ctx->frag_extra_bytes = 0;
    ignore = false;

    ret = fota_candidate_extract_start(force_encrypt, expected_comp_name, install_alignment);
    if (ret) {
        goto fail;
    }

    memset(&cb_info, 0, sizeof(cb_info));

    cb_info.status = FOTA_CANDIDATE_ITERATE_START;
    cb_info.header_info = &ctx->header_info;
    ret = handler(&cb_info);
    if (ret) {
        FOTA_TRACE_ERROR("Candidate user handler failed on start, ret %d", ret);
        goto fail;
    }

    do {
        ret = fota_candidate_extract_fragment(&buf, &actual_size, &ignore);
        if (ret) {
            goto fail;
        }
        if (ignore) {
            continue;
        }
        cb_info.status = FOTA_CANDIDATE_ITERATE_FRAGMENT;
        cb_info.frag_size = actual_size;
        cb_info.frag_buf = buf;
        ret = handler(&cb_info);
        if (ret) {
            FOTA_TRACE_ERROR("Candidate user handler failed on fragment, ret %d", ret);
            goto fail;
        }
        cb_info.frag_pos += actual_size;
    } while (cb_info.frag_pos < ctx->header_info.fw_size);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->header_info.flags & FOTA_HEADER_ENCRYPTED_FLAG) {
        fota_encrypt_finalize(&ctx->enc_ctx);
    }
#endif

    cb_info.status = FOTA_CANDIDATE_ITERATE_FINISH;
    ret = handler(&cb_info);
    if (ret) {
        FOTA_TRACE_ERROR("Candidate user handler failed on finish, ret %d", ret);
        goto fail;
    }

fail:
    if (hash_ctx) {
        fota_hash_finish(&hash_ctx);
    }
    cleanup();
    return ret;
}

int fota_candidate_erase(void)
{
    size_t erase_size;
    int ret = fota_bd_get_erase_size(fota_candidate_get_config()->storage_start_addr, &erase_size);
    if (ret) {
        return ret;
    }
    ret = fota_bd_erase(fota_candidate_get_config()->storage_start_addr, erase_size);
    return ret;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
