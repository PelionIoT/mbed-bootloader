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

#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

typedef struct {
    fota_component_desc_t desc;
    fota_component_version_t version;
} comp_entry_t;

static unsigned int num_components = 0;
static comp_entry_t comp_table[FOTA_NUM_COMPONENTS];

#define MAJOR_NUM_BITS 24
#define MINOR_NUM_BITS 24
#define SPLIT_NUM_BITS 16
#define MAX_VER 999

void fota_component_clean(void)
{
    num_components = 0;
    memset(comp_table, 0, sizeof(comp_table));
}

int fota_component_add(const fota_component_desc_t *comp_desc)
{
    FOTA_ASSERT(num_components < FOTA_NUM_COMPONENTS);
    FOTA_ASSERT(!(comp_desc->support_delta && (!comp_desc->curr_fw_get_digest || !comp_desc->curr_fw_read)));

    memcpy(&comp_table[num_components].desc, comp_desc, sizeof(fota_component_desc_t));

    num_components++;
    return FOTA_STATUS_SUCCESS;
}

unsigned int fota_component_num_components(void)
{
    return num_components;
}

void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc)
{
    FOTA_ASSERT(comp_id < num_components)
    *comp_desc = &comp_table[comp_id].desc;
}

void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version)
{
    FOTA_ASSERT(comp_id < num_components)
    *version = comp_table[comp_id].version;
}

void fota_component_set_curr_version(unsigned int comp_id, fota_component_version_t version)
{
    FOTA_ASSERT(comp_id < num_components)
    comp_table[comp_id].version = version;
}

int fota_component_name_to_id(const char *name, unsigned int *comp_id)
{
    int i = num_components;

    // One or more components
    do {
        if (!strcmp(name, comp_table[num_components - i].desc.name)) {
            *comp_id = num_components - i;
            return FOTA_STATUS_SUCCESS;
        }
    } while (--i);

    return FOTA_STATUS_NOT_FOUND;
}

int fota_component_version_int_to_semver(fota_component_version_t version, char *sem_ver)
{
    uint64_t major, minor, split;
    uint64_t full_mask = 0xFFFFFFFFFFFFFFFFULL;
    int ret = FOTA_STATUS_SUCCESS;

    split = version & ~(full_mask << SPLIT_NUM_BITS);
    minor = (version & ~(full_mask << (SPLIT_NUM_BITS + MINOR_NUM_BITS))) >> SPLIT_NUM_BITS;
    major = version >> (SPLIT_NUM_BITS + MINOR_NUM_BITS);

    if ((major > MAX_VER) || (minor > MAX_VER) || (split > MAX_VER)) {
        ret = FOTA_STATUS_INVALID_ARGUMENT;
    }

    split = MIN(split, MAX_VER);
    minor = MIN(minor, MAX_VER);
    major = MIN(major, MAX_VER);

    sprintf(sem_ver, "%" PRIu64 ".%" PRIu64 ".%" PRIu64, major, minor, split);

    return ret;
}

int fota_component_version_semver_to_int(const char *sem_ver, fota_component_version_t *version)
{
    // This better use signed strtol() instead of strtoul() as it is already used by other code
    // and there is no need to add more dependencies here. That change saves ~120B.
    int64_t major, minor, split;
    char *endptr;
    int ret = FOTA_STATUS_SUCCESS;

    major = strtol(sem_ver, &endptr, 10);
    minor = strtol(endptr + 1, &endptr, 10);
    split = strtol(endptr + 1, &endptr, 10);
    FOTA_DBG_ASSERT((endptr - sem_ver) <= FOTA_COMPONENT_MAX_SEMVER_STR_SIZE);

    if ((major < 0) || (major > MAX_VER) ||
            (minor < 0) || (minor > MAX_VER) ||
            (split < 0) || (split > MAX_VER)) {
        ret = FOTA_STATUS_INVALID_ARGUMENT;

        // Unfortunately not all call sites of this handle the error, so this might as well
        // give stable output on error path too.
        *version = 0;
    } else {

        split = MIN(split, MAX_VER);
        minor = MIN(minor, MAX_VER);
        major = MIN(major, MAX_VER);

        *version = split | minor << SPLIT_NUM_BITS | major << (SPLIT_NUM_BITS + MINOR_NUM_BITS);
    }
    return ret;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
