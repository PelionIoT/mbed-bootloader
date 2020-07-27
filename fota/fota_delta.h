// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
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

#ifndef __FOTA_DELTA_H_
#define __FOTA_DELTA_H_

#if !defined(FOTA_DISABLE_DELTA)

#include "fota/fota_base.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fota_delta_ctx_s fota_delta_ctx_t;

int fota_delta_start(fota_delta_ctx_t **ctx, fota_component_curr_fw_read curr_fw_read);
int fota_delta_get_next_fw_frag(
    fota_delta_ctx_t *ctx,
    uint8_t *fw_frag, uint32_t fw_frag_buf_size,
    uint32_t *fw_frag_actual_size);
int fota_delta_new_payload_frag(
    fota_delta_ctx_t *ctx,
    const uint8_t *payload_frag, uint32_t payload_frag_size);
int fota_delta_payload_finished(fota_delta_ctx_t *ctx);
int fota_delta_finalize(fota_delta_ctx_t **ctx);

#ifdef __cplusplus
}
#endif

#endif  // !defined(FOTA_DISABLE_DELTA)

#endif // __FOTA_DELTA_H_
