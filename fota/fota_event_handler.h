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
#ifndef FOTA_FOTA_EVENT_HANDLER_H_
#define FOTA_FOTA_EVENT_HANDLER_H_

#include "fota_internal.h"

typedef  void (*fota_deferred_data_callabck_t)(uint8_t *data, size_t size);
typedef  void (*fota_deferred_result_callabck_t)(uint32_t token, int32_t status);

/*
 * Initialize event handler
 *
 * Allocate and initialize FOTA event handler context
 * /return FOTA_STATUS_SUCCESS on success
 */
int fota_event_handler_init(void);

/*
 * Deinitialize FOTA event handler context
 *
 * Free resources and zero the pointer
 */
void fota_event_handler_deinit(void);

/*
 * Defer execution of a FOTA callback with a data buffer
 *
 * The deferred callback will run in its own time slot
 *
 * /param cb[in] callback function pointer to be deferred
 * /param data[in] deferred callback input data pointer
 * /param size[in] deferred callback input data size
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_event_handler_defer_with_data(
    fota_deferred_data_callabck_t cb, uint8_t *data, size_t size);

/*
 * Defer execution of a FOTA callback with error details
 * /param cb callback function pointer to be deferred
 * /param token callback token - used by FOTA application interfaces
 * /status a status code
 */
void fota_event_handler_defer_with_result(
    fota_deferred_result_callabck_t cb, uint32_t token, int32_t status);

#endif // FOTA_FOTA_EVENT_HANDLER_H_
