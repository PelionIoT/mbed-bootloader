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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include <stdlib.h>
#include "mbed-client-libservice/ns_types.h"
#include "nanostack-event-loop/eventOS_event.h"
#include "fota/fota_status.h"
#include "fota/fota_event_handler.h"

#define FOTA_EVENT_INIT                1
#define FOTA_EVENT_EXECUTE_WITH_BUFFER 2
#define FOTA_EVENT_EXECUTE_WITH_RESULT 4

typedef struct {
    uint8_t *data;
    size_t size;
} fota_cb_buffer_t;

typedef struct {
    uint32_t token;
    int32_t  status;
} fota_cb_token_t;

typedef union {
    fota_cb_buffer_t buffer;
    fota_cb_token_t result;
} fota_cb_args_t;


typedef struct {
    arm_event_storage_t event_storage;
    void *cb;
    fota_cb_args_t args;
    bool is_pending_event;
    int8_t tasklet_id;
} fota_event_handler_ctx_t;

static fota_event_handler_ctx_t g_ctx = { 0 };

static void event_handler(arm_event_t *event)
{
    FOTA_TRACE_DEBUG("FOTA event-handler got event [type= %d]", event->event_type);

    switch (event->event_type) {
        case FOTA_EVENT_EXECUTE_WITH_BUFFER:
        case FOTA_EVENT_EXECUTE_WITH_RESULT:
            break;

        case FOTA_EVENT_INIT:
            return; // ignore event - nothing to be done
        default:
            FOTA_DBG_ASSERT(!"Unknown event");
    }

    fota_event_handler_ctx_t *ctx = (fota_event_handler_ctx_t *)event->data_ptr;
    FOTA_DBG_ASSERT(ctx == &g_ctx);
    FOTA_DBG_ASSERT(ctx->is_pending_event);

    ctx->is_pending_event = false;

    if (event->event_type == FOTA_EVENT_EXECUTE_WITH_BUFFER) {

        fota_deferred_data_callabck_t cb = (fota_deferred_data_callabck_t)ctx->cb;

        // backup the pointer as we need it after the callback.
        // since we are setting ctx->is_pending_event = false - it may be overwritten
        uint8_t *cb_data = ctx->args.buffer.data;

        cb(ctx->args.buffer.data, ctx->args.buffer.size);
        free((void *)cb_data);

    } else { // FOTA_EVENT_EXECUTE_WITH_RESULT

        fota_deferred_result_callabck_t cb = (fota_deferred_result_callabck_t)ctx->cb;
        cb(ctx->args.result.token, ctx->args.result.status);
    }
}

int fota_event_handler_init(void)
{
    FOTA_ASSERT(!g_ctx.is_pending_event);

    memset(&g_ctx, 0, sizeof(g_ctx));

    g_ctx.tasklet_id = eventOS_event_handler_create(event_handler, FOTA_EVENT_INIT);
    FOTA_ASSERT(g_ctx.tasklet_id >= 0);

    return FOTA_STATUS_SUCCESS;
}


void fota_event_handler_deinit(void)
{
    FOTA_ASSERT(!g_ctx.is_pending_event);
    //nothing to de-register - eventOS does not have a method for destroying handlers
}

int fota_event_handler_defer_with_data(
    fota_deferred_data_callabck_t cb, uint8_t *data, size_t size)
{
    FOTA_ASSERT(!g_ctx.is_pending_event);
    g_ctx.is_pending_event = true;
    g_ctx.cb = (void *)cb;
    g_ctx.args.buffer.size = size;
    if (size) {
        uint8_t *tmp_data_ptr = (uint8_t *) malloc(size);
        if (!tmp_data_ptr) {
            FOTA_TRACE_ERROR("FOTA tmp_data_ptr - allocation failed");
            return FOTA_STATUS_OUT_OF_MEMORY;
        }
        memcpy(tmp_data_ptr, data, size);
        g_ctx.args.buffer.data = tmp_data_ptr;
    } else {
        g_ctx.args.buffer.data = NULL;
    }

    g_ctx.event_storage.data.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    g_ctx.event_storage.data.receiver = g_ctx.tasklet_id;
    g_ctx.event_storage.data.event_type  = FOTA_EVENT_EXECUTE_WITH_BUFFER;
    g_ctx.event_storage.data.data_ptr = (void *)&g_ctx;

    eventOS_event_send_user_allocated(&g_ctx.event_storage);

    return FOTA_STATUS_SUCCESS;
}

void fota_event_handler_defer_with_result(
    fota_deferred_result_callabck_t cb, uint32_t token, int32_t status)
{
    FOTA_ASSERT(!g_ctx.is_pending_event);
    g_ctx.is_pending_event = true;
    g_ctx.cb = (void *)cb;
    g_ctx.args.result.token = token;
    g_ctx.args.result.status = status;

    g_ctx.event_storage.data.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    g_ctx.event_storage.data.receiver = g_ctx.tasklet_id;
    g_ctx.event_storage.data.event_type  = FOTA_EVENT_EXECUTE_WITH_RESULT;
    g_ctx.event_storage.data.data_ptr = (void *)&g_ctx;

    eventOS_event_send_user_allocated(&g_ctx.event_storage);
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
