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

#ifndef __FOTA_H_
#define __FOTA_H_

#include "fota/fota_config.h"

#if MBED_CLOUD_CLIENT_FOTA_ENABLE

// TODO: move to delta -  when integrated
#if !defined(MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE 1024
#endif


#include "fota/fota_status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct endpoint_s endpoint_t;

/*
 * Initialize Pelion FOTA component.
 *
 * This method should be called once on system strut-up.
 * \param[in] in_endpoint Mbed Cloud Client Lite LWM2M Endpoint instance
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_init(endpoint_t *in_endpoint);

/*
 * Deinitialize Pelion FOTA component.
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_deinit(void);

#ifdef __cplusplus
}
#endif

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE

#endif // __FOTA_H_
