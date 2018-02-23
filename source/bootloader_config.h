// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#ifndef BOOTLOADER_CONFIG_H
#define BOOTLOADER_CONFIG_H

/* MAX_FIRMWARE_LOCATIONS */
#if defined(MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) && \
    MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS > 0
#define MAX_FIRMWARE_LOCATIONS MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS
#endif

#if !defined(MAX_FIRMWARE_LOCATIONS) || MAX_FIRMWARE_LOCATIONS <= 0
#error "configure update-client.storage-locations or MAX_FIRMWARE_LOCATIONS in mbed_app.json\n" \
       "To use pre configured profiles: mbed compile --app-config configs/<config>.json"
#endif

/* FIRMWARE_METADATA_HEADER_ADDRESS */
#if defined(MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS)
#define FIRMWARE_METADATA_HEADER_ADDRESS MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS
#endif

#if !defined(FIRMWARE_METADATA_HEADER_ADDRESS)
#error "configure update-client.application-details or FIRMWARE_METADATA_HEADER_ADDRESS in mbed_app.json\n" \
       "To use pre configured profiles: mbed compile --app-config configs/<config>.json"
#endif

/* FIRMWARE_METADATA_HEADER_SIZE */
#if defined(MBED_CONF_APP_APPLICATION_START_ADDRESS) && \
    defined(FIRMWARE_METADATA_HEADER_ADDRESS)
#define FIRMWARE_METADATA_HEADER_SIZE \
            (MBED_CONF_APP_APPLICATION_START_ADDRESS - \
             FIRMWARE_METADATA_HEADER_ADDRESS)
#endif

#if !defined(FIRMWARE_METADATA_HEADER_SIZE)
#error "configure application_start_address in mbed_app.json\n" \
       "To use pre configured profiles: mbed compile --app-config configs/<config>.json"
#endif

#endif // BOOTLOADER_CONFIG_H
