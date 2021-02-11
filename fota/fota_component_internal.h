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

#ifndef __FOTA_COMPONENT_INTERNAL_H_
#define __FOTA_COMPONENT_INTERNAL_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    fota_component_version_t version;
    fota_component_desc_info_t desc_info;
    char name[FOTA_COMPONENT_MAX_NAME_SIZE];
} fota_component_desc_t;

// Component access APIs
void fota_component_clean(void);
unsigned int fota_component_num_components(void);
void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc);
void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version);
void fota_component_set_curr_version(unsigned int comp_id, fota_component_version_t version);

int fota_component_name_to_id(const char *name, unsigned int *comp_id);

// Semantic version translation
int fota_component_version_semver_to_int(const char *sem_ver, fota_component_version_t *version);

bool fota_component_is_internal_component(unsigned int comp_id);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_COMPONENT_INTERNAL_H_
