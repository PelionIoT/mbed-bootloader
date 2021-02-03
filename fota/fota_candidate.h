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

#ifndef __FOTA_CANDIDATE_H_
#define __FOTA_CANDIDATE_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_header_info.h"
#include "fota/fota_crypto_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Candidate iterate status
 *
 * This status code is passed to user supplied fota_candidate_iterate_handler_t callback function.
 */
typedef enum {
    FOTA_CANDIDATE_ITERATE_START,  /**< sent once on candidate iteration start event */
    FOTA_CANDIDATE_ITERATE_FRAGMENT, /**< sent multiple times - once per extracted candidate fragment */
    FOTA_CANDIDATE_ITERATE_FINISH,  /**< sent once on candidate iteration finish event */
} fota_candidate_iterate_status;

// Block checksum (in case of resume and non encrypted blocks)
typedef uint16_t fota_candidate_block_checksum_t;

/**
 * Candidate iterate callback info
 *
 * status iterate status.
 * frag_size fragment size.
 * frag_pos fragment position.
 * frag_buf fragment buffer.
 * header_info candidate header info.
 * user_ctx user data, which lives between the calls to the callbacks
 */
typedef struct {
    fota_candidate_iterate_status status;
    size_t frag_size;
    size_t frag_pos;
    uint8_t  *frag_buf;
    fota_header_info_t *header_info;
    void *user_ctx;
} fota_candidate_iterate_callback_info;

/**
 * Candidate config info
 *
 * storage_size storage size used for candidate.
 * storage_start_addr storage start address for candidate.
 */
typedef struct {
    size_t    storage_size;
    size_t    storage_start_addr;
} fota_candidate_config_t;

/**
 * Set candidate config. Relevant only for tests, takes input from configurations by default.
 *
 * \param[in] in_fota_candidate_config Candidate config.
 * \return FOTA_STATUS_SUCCESS on success.
 */
void fota_candidate_set_config(fota_candidate_config_t *in_fota_candidate_config);

/**
 * Get candidate config.
 *
 * \return pointer to candidate config.
 */
const fota_candidate_config_t *fota_candidate_get_config(void);

/**
 * Callback called on iteration start, each fragment and finish.
 *
 * \param[in] info iterate callback info.
 * \return FOTA_STATUS_SUCCESS on success.
 */
typedef int (*fota_candidate_iterate_handler_t)(fota_candidate_iterate_callback_info *info);

#define FOTA_CANDIDATE_SKIP_VALIDATION 0x27

/**
 * Iterate on candidate image.
 *
 * \param[in] validate optionally validate image on storage, could add significant time to validate candidate.
 * \param[in] force_encrypt force encryption.
 * \param[in] expected_comp_name expected component name.
 * \param[in] install_alignment  installer alignment in bytes.
 * \param[in] handler callback called on iteration start, each fragment and finish.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_candidate_iterate_image(uint8_t validate, bool force_encrypt, const char *expected_comp_name,
                                 uint32_t install_alignment, fota_candidate_iterate_handler_t handler);

/**
 * Read candidate component ready header.
 *
 * \param[in,out] addr candidate header address.
 * \param[in] bd_read_size bd read size.
 * \param[in] bd_prog_size bd program size.
 * \param[out] header candidate ready header.
 * \return FOTA_STATUS_SUCCESS if found.
 */
int fota_candidate_read_candidate_ready_header(size_t *addr, uint32_t bd_read_size, uint32_t bd_prog_size,
                                               fota_candidate_ready_header_t *header);

/**
 * Read candidate image header.
 *
 * \param[in,out] addr image header address.
 * \param[in] bd_read_size bd read size.
 * \param[in] bd_prog_size bd program size.
 * \param[out] header image header info.
 * \return FOTA_STATUS_SUCCESS if found.
 */
int fota_candidate_read_header(size_t *addr, uint32_t bd_read_size, uint32_t bd_prog_size, fota_header_info_t *header);

/**
 * Erase current candidate.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_candidate_erase(void);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_CANDIDATE_H_
