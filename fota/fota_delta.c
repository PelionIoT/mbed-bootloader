// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#if !defined(FOTA_DISABLE_DELTA)

#include "fota/fota_delta.h"

#include "fota/fota_status.h"
#include "fota/fota_header_info.h"
#include "update-client-hub/delta-tool-internal/include/bspatch.h"
#include "update-client-hub/delta-tool-internal/include/bspatch_private.h" //For bspatch_stream

#include <inttypes.h>
#include <stdlib.h>

#ifdef FOTA_DELTA_DEBUG
#define DBG FOTA_TRACE_DEBUG
#else
#define DBG(fmt, ...)
#endif


typedef struct fota_delta_ctx_s {
    struct bspatch_stream bs_patch_stream;
    // To keep internal state of which bspatch event is currently going to be completed
    bs_patch_api_event_t next_event_to_post;
    // to store bspatch original seek diff and use it in original read
    int64_t bspatch_seek_diff;
    // to keep pointer to buffer bspatch gives us to read_patch function
    void *bspatch_read_patch_buffer_ptr;
    // to keep length what size buffer bspatch gave into read_patch function
    uint32_t bspatch_read_patch_buffer_length;
    // to keep size how much we have remaining to be consumed from buffer bspatch gave into read_patch function
    uint32_t bspatch_read_patch_buffer_remaining;
    // Pointer to data waiting for BS patch
    const uint8_t *incoming_frag_ptr;
    // Size of data waiting for BS patch
    uint32_t incoming_frag_size;
    // to keep offset how much of incoming data BS patch is used
    uint32_t incoming_frag_ptr_offset;
    // pointer to final image fragment
    uint8_t *outgoing_frag_ptr;
    // Size of final image fragment
    uint32_t outgoing_frag_size;
    // To keep offset how much outcoming fragment is used
    uint32_t outgoing_frag_ptr_offset;
    // current fw reader function
    fota_component_curr_fw_read curr_fw_read;
} fota_delta_ctx_t;

/*
 * BsPatch callback function to Read data from the original file/image
 *
 * \param stream pointer to bspatch_stream
 * \param buffer buffer where read data should be stored
 * \param length amount to read
 *
 * \return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY or error code
 */
bs_patch_api_return_code_t original_read(const struct bspatch_stream *stream, void *buffer, uint64_t length);

/*
 * BsPatch callback function to Read Patch/Delta data/payload
 *
 * \param stream pointer to bspatch_stream
 * \param buffer buffer where read the data to
 * \param length amount of data to read
 *
 * \return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY or error code
 */
bs_patch_api_return_code_t read_patch(const struct bspatch_stream *stream, void *buffer, uint32_t length);

/*
  * BsPatch callback function to Seek the original file/image
  *
  * \param stream pointer to bspatch_stream
  * \param seek_diff distance to move the file pointer in original image
  *
  * \return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY
  */
bs_patch_api_return_code_t original_seek(const struct bspatch_stream *stream, int64_t seek_diff);

/**
 * BsPatch callback function to Write data into the new image
 *
 * \param stream pointer to bspatch_stream
 * \param buffer buffer where piece of new image for write request can be found
 * \param length amount of new image in the buffer
 *
 * \return bs_patch_api_return_code_t EBSAPI_OPERATION_DONE_IMMEDIATELY or error
 */
bs_patch_api_return_code_t new_write(const struct bspatch_stream *stream, void *buffer, uint64_t length);

/*
 *Will loop BS patch event
 */
int do_patching(fota_delta_ctx_t *delta_ctx);

int fota_delta_start(fota_delta_ctx_t **ctx, fota_component_curr_fw_read curr_fw_read)
{
    FOTA_DBG_ASSERT(ctx);

    fota_delta_ctx_t *delta_ctx = (fota_delta_ctx_t *) malloc(sizeof(fota_delta_ctx_t));
    if (!delta_ctx) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    memset(delta_ctx, 0, sizeof(*delta_ctx));
    delta_ctx->next_event_to_post = EBSAPI_START_PATCH_PROCESSING;
    delta_ctx->bspatch_read_patch_buffer_remaining = 0;
    delta_ctx->bspatch_read_patch_buffer_length = 0;
    delta_ctx->bspatch_seek_diff = 0;
    delta_ctx->incoming_frag_size = 0;
    delta_ctx->incoming_frag_ptr_offset = 0;
    delta_ctx->incoming_frag_ptr = 0;
    delta_ctx->curr_fw_read = curr_fw_read;
    ARM_BS_Init(&delta_ctx->bs_patch_stream, (void *)delta_ctx,
                read_patch,
                original_read,
                original_seek,
                new_write);

    *ctx = delta_ctx;
    return FOTA_STATUS_SUCCESS;
}

int fota_delta_new_payload_frag(
    fota_delta_ctx_t *ctx,
    const uint8_t *payload_frag, uint32_t payload_frag_size)
{
    FOTA_DBG_ASSERT(ctx);
    DBG("[DELTA] fota_delta_new_payload_frag payload_frag_size=%d", payload_frag_size);
    ctx->incoming_frag_size = payload_frag_size;
    ctx->incoming_frag_ptr_offset = 0;
    ctx->incoming_frag_ptr = payload_frag;

    // If read_patch was not completed because not enough buffers (amount of data is open)
    // Copy what we can fit into bspatch read_patch buffer
    if (ctx->next_event_to_post == EBSAPI_READ_PATCH_DONE &&
            ctx->bspatch_read_patch_buffer_remaining > 0 &&
            ctx->bspatch_read_patch_buffer_remaining <= ctx->bspatch_read_patch_buffer_length) {
        uint32_t incoming_bytes_copy = payload_frag_size < ctx->bspatch_read_patch_buffer_remaining ? payload_frag_size : ctx->bspatch_read_patch_buffer_remaining;
        uint32_t patch_buf_offset = ctx->bspatch_read_patch_buffer_length - ctx->bspatch_read_patch_buffer_remaining;
        memcpy((uint8_t *)(ctx->bspatch_read_patch_buffer_ptr) + (patch_buf_offset),
               payload_frag,
               incoming_bytes_copy);
        ctx->incoming_frag_ptr_offset += incoming_bytes_copy;
        ctx->bspatch_read_patch_buffer_remaining -= incoming_bytes_copy;
    }
    if (ctx->bspatch_read_patch_buffer_remaining == 0) {
        return do_patching(ctx);
    } else {
        return FOTA_STATUS_FW_DELTA_REQUIRED_MORE_DATA;
    }
}

int fota_delta_get_next_fw_frag(
    fota_delta_ctx_t *ctx,
    uint8_t *fw_frag, uint32_t fw_frag_buf_size,
    uint32_t *fw_frag_actual_size)
{
    FOTA_DBG_ASSERT(ctx);

    int status = FOTA_STATUS_SUCCESS;
    DBG("[DELTA] fota_delta_get_next_fw_frag next_event_to_post=%d outgoing_frag_size=%d", ctx->next_event_to_post, ctx->outgoing_frag_size);
    if (ctx->outgoing_frag_ptr == NULL &&
            ctx->outgoing_frag_size == 0) {
        // if nothing to copy
        *fw_frag_actual_size = 0;
    } else if (ctx->next_event_to_post == EBSAPI_WRITE_NEW_DONE) {
        // only copy data if EBSAPI_WRITE_NEW_DONE
        uint32_t copy_amount = fw_frag_buf_size;
        if (fw_frag_buf_size > ctx->outgoing_frag_size - ctx->outgoing_frag_ptr_offset) {
            copy_amount = ctx->outgoing_frag_size - ctx->outgoing_frag_ptr_offset;
        }
        memcpy(fw_frag, ctx->outgoing_frag_ptr + ctx->outgoing_frag_ptr_offset, copy_amount);
        *fw_frag_actual_size = copy_amount;
        ctx->outgoing_frag_ptr_offset += copy_amount;
        // Check if end of fragment buffer
        // Continue patching
        if (ctx->outgoing_frag_ptr_offset >= ctx->outgoing_frag_size) {
            status = do_patching(ctx);
        }
    } else {
        // if nothing to copy
        *fw_frag_actual_size = 0;
    }

    return status;
}

int fota_delta_payload_finished(fota_delta_ctx_t *ctx)
{
    FOTA_DBG_ASSERT(ctx);
    (void)ctx;  // unused warning;

    // TODO: add FOTA_DBG_ASSERT() for internal current state
    return FOTA_STATUS_SUCCESS;
}

int fota_delta_finalize(fota_delta_ctx_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    int status = FOTA_STATUS_SUCCESS;
    if (*ctx) {

        // bspatch read is still waiting for data
        if ((*ctx)->bspatch_read_patch_buffer_remaining > 0) {
            FOTA_TRACE_ERROR("[DELTA] fota_delta_finalize bspatch read is still waiting for data %" PRIu32 " bytes.", (*ctx)->bspatch_read_patch_buffer_remaining);
            status = FOTA_STATUS_INTERNAL_DELTA_ERROR;
        }

        ARM_BS_Free(&(*ctx)->bs_patch_stream);
        free(*ctx);
        *ctx = NULL;
    }
    return status;
}

int do_patching(fota_delta_ctx_t *delta_ctx)
{
    bs_patch_api_return_code_t bs_result = EBSAPI_ERR_INVALID_STATE;
    do {
        bs_result = ARM_BS_ProcessPatchEvent(&delta_ctx->bs_patch_stream, delta_ctx->next_event_to_post);
        if (bs_result == EBSAPI_PATCH_DONE ||
                bs_result == EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER ||
                bs_result == EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER) {
            break;
        } else if (bs_result < EBSAPI_OPERATION_DONE_IMMEDIATELY) {  // for all the failure error codes
            DBG("[DELTA] ARM_BS_ProcessPatchEvent() = %d.", bs_result);
            ARM_BS_Free(&delta_ctx->bs_patch_stream);
            if (bs_result == EBSAPI_ERR_OUT_OF_MEMORY) {
                FOTA_TRACE_ERROR("[DELTA] failed to allocate storage - try to reduce compression block size");
                return FOTA_STATUS_INTERNAL_DELTA_ERROR;
            }
            return FOTA_STATUS_INTERNAL_DELTA_ERROR;
        }
    } while ((delta_ctx->incoming_frag_size - delta_ctx->incoming_frag_ptr_offset) > 0);
    return FOTA_STATUS_SUCCESS;
}

bs_patch_api_return_code_t read_patch(
    const struct bspatch_stream *stream,
    void *buffer,
    uint32_t length)
{
    bs_patch_api_return_code_t return_code = EBSAPI_ERR_UNEXPECTED_EVENT;
    uint32_t copy_amount = 0;
    fota_delta_ctx_t *delta_ctx = (fota_delta_ctx_t *)stream->opaque;
    FOTA_DBG_ASSERT(delta_ctx);
    delta_ctx->bspatch_read_patch_buffer_ptr = buffer;
    delta_ctx->bspatch_read_patch_buffer_length = length;
    delta_ctx->bspatch_read_patch_buffer_remaining = length;

    // there aren't enough data waiting. Copy what we have and wait for more
    if (length > (delta_ctx->incoming_frag_size - delta_ctx->incoming_frag_ptr_offset)) {
        // We need to signal main bspatch-loop we have (in Write?)
        // to break so that we can get more patch data in.
        DBG("[DELTA] read_patch(length=%" PRIu32 ") EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER", length);
        copy_amount = (uint64_t)(delta_ctx->incoming_frag_size - delta_ctx->incoming_frag_ptr_offset);
        return_code = EBSAPI_OPERATION_PATCH_READ_WILL_COMPLETE_LATER;

    } else {
        DBG("[DELTA] read_patch(length=%" PRIu32 ") EBSAPI_OPERATION_DONE_IMMEDIATELY", length);
        copy_amount = length;
        return_code = EBSAPI_OPERATION_DONE_IMMEDIATELY;
    }
    memcpy(buffer, delta_ctx->incoming_frag_ptr + delta_ctx->incoming_frag_ptr_offset, copy_amount);
    delta_ctx->bspatch_read_patch_buffer_remaining -= copy_amount;
    delta_ctx->incoming_frag_ptr_offset += (uint32_t)copy_amount;
    delta_ctx->next_event_to_post = EBSAPI_READ_PATCH_DONE;
    return return_code;
}

bs_patch_api_return_code_t original_read(
    const struct bspatch_stream *stream,
    void *buffer,
    uint64_t length)
{
    fota_delta_ctx_t *delta_ctx = (fota_delta_ctx_t *)stream->opaque;
    FOTA_DBG_ASSERT(delta_ctx);
    // always return 0. No need to check
    uint32_t num_read = 0;
    int status = delta_ctx->curr_fw_read(buffer, (uint32_t)delta_ctx->bspatch_seek_diff, length, &num_read);
    if ((status == 0) || (num_read == length)) {
        DBG("[DELTA] original_read(offset=%" PRIu64 ", length=%" PRIu64 ")", delta_ctx->bspatch_seek_diff, length);
        delta_ctx->bspatch_seek_diff += length;
        return EBSAPI_OPERATION_DONE_IMMEDIATELY;
    }
    FOTA_TRACE_ERROR("[DELTA] failed to read current FW");
    return EBSAPI_ERR_FILE_IO;
}

bs_patch_api_return_code_t original_seek(
    const struct bspatch_stream *stream,
    int64_t seek_diff)
{
    DBG("[DELTA] original_seek(seek_diff=%" PRId64 ")", seek_diff);
    fota_delta_ctx_t *delta_ctx = (fota_delta_ctx_t *)stream->opaque;
    FOTA_DBG_ASSERT(delta_ctx);

    delta_ctx->bspatch_seek_diff += seek_diff;
    delta_ctx->next_event_to_post = EBSAPI_SEEK_OLD_DONE;
    return EBSAPI_OPERATION_DONE_IMMEDIATELY;
}

bs_patch_api_return_code_t new_write(
    const struct bspatch_stream *stream,
    void *buffer,
    uint64_t length)
{
    fota_delta_ctx_t *delta_ctx = (fota_delta_ctx_t *)stream->opaque;
    FOTA_DBG_ASSERT(delta_ctx);

    DBG("[DELTA] new_write(length=%" PRIu64 ")", length);

    delta_ctx->outgoing_frag_ptr = (uint8_t *)buffer;
    delta_ctx->outgoing_frag_size = length;
    delta_ctx->outgoing_frag_ptr_offset = 0;
    delta_ctx->next_event_to_post = EBSAPI_WRITE_NEW_DONE;
    return EBSAPI_OPERATION_NEW_FILE_WRITE_WILL_COMPLETE_LATER;
}

// fot tests only
#if defined(FOTA_UNIT_TEST)
struct bspatch_stream *fota_get_bs_patch_stream(void *ctx)
{
    FOTA_DBG_ASSERT(ctx);
    fota_delta_ctx_t *delta_ctx = (fota_delta_ctx_t *)ctx;
    return &delta_ctx->bs_patch_stream;
}
#endif  // defined(FOTA_UNIT_TEST)

#endif  // !defined(FOTA_DISABLE_DELTA)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
