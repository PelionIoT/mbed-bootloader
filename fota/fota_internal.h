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

#ifndef __FOTA_INTERNAL_H_
#define __FOTA_INTERNAL_H_

#include "fota/fota_base.h"
#include "fota/fota_manifest.h"
#include "fota/fota_app_ifs.h"
#include "fota/fota_delta.h"
#include "fota/fota_header_info.h"
#include "fota/fota_crypto.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FOTA_STATE_IDLE = 0, // must be zero as it is set by zeroing entire FOTA context at init
    FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION,
    FOTA_STATE_DOWNLOADING,
    FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION,
    FOTA_STATE_INVALID = 255,
} fota_state_e;

typedef enum {
    FOTA_RESUME_STATE_INACTIVE = 0, // must be zero as it is set by zeroing entire FOTA context at init
    FOTA_RESUME_STATE_STARTED,
    FOTA_RESUME_STATE_ONGOING,
} fota_resume_state_e;

typedef struct {
    manifest_firmware_info_t *fw_info;
    uint32_t payload_offset;
    uint32_t fw_bytes_written;
    uint32_t auth_token;
    unsigned int comp_id;
    fota_state_e state;
    uint32_t frag_size;
#if !defined(FOTA_DISABLE_DELTA)
    uint8_t *delta_buf;
    fota_delta_ctx_t *delta_ctx;
#endif
    fota_encrypt_context_t *enc_ctx;
    fota_hash_context_t *curr_fw_hash_ctx;
    uint8_t *page_buf;
    uint32_t page_buf_offset;
    uint32_t page_buf_size;
    uint8_t *effective_page_buf;
    uint32_t effective_page_buf_size;
    uint32_t storage_addr;
    uint32_t fw_header_bd_size;
    uint32_t fw_header_offset;
    uint32_t candidate_header_size;
    fota_resume_state_e resume_state;
} fota_context_t;

fota_context_t *fota_get_context(void);

bool fota_is_active_update(void);
int  fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state);

void fota_on_manifest(uint8_t *data, size_t size);
void fota_on_reject(uint32_t token, int32_t status);
void fota_on_defer(uint32_t token, int32_t status);
void fota_on_authorize(uint32_t token, int32_t status);
void fota_on_fragment(uint8_t *buf, size_t size);
void fota_on_fragment_failure(uint32_t token, int32_t status);
void fota_on_resume(uint32_t token, int32_t status);
#ifdef __cplusplus
}
#endif

#endif // __FOTA_INTERNAL_H_
