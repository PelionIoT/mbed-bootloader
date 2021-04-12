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

#include "fota/fota_base.h"
#include <stdlib.h>

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

static unsigned int num_user_components = 0;
static fota_component_desc_t user_comp_table[FOTA_NUM_COMPONENTS];
#define INT_COMP_ID_FLAG 0x80000000
#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
// Internal components - not reported to service
static unsigned int num_int_components = 0;
static fota_component_desc_t *int_comp_table;
#endif

#define MAJOR_NUM_BITS 23
#define MINOR_NUM_BITS 24
#define SPLIT_NUM_BITS 16
#define MAX_VER 999

//num is between 0 and 999 (MAX_VER)
static char *append_number_to_string(char *str, uint_fast16_t num, char trail)
{
    if (num >= 100) {
        char p = '0' + num / 100;
        *str++ = p;
    }
    if (num >= 10) {
        *str++ = '0' + (num % 100) / 10;
    }
    *str++ = '0' + (num % 10);
    *str++ = trail;
    return str;
}

void fota_component_clean(void)
{
    num_user_components = 0;
    memset(user_comp_table, 0, sizeof(user_comp_table));
#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
    num_int_components = 0;
    free(int_comp_table);
    int_comp_table = NULL;
#endif
}

#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
static inline void comp_id_translate(unsigned int *comp_id, fota_component_desc_t * *comp_table, unsigned int *num_components)
{
    if (*comp_id & INT_COMP_ID_FLAG) {
        *comp_id &= ~INT_COMP_ID_FLAG;
        *comp_table = int_comp_table;
        *num_components = num_int_components;
    } else {
        *comp_table = user_comp_table;
        *num_components = num_user_components;
    }
}

#endif

bool fota_component_is_internal_component(unsigned int comp_id)
{
    return (comp_id & INT_COMP_ID_FLAG) ? true : false;
}

int fota_component_add(const fota_component_desc_info_t *comp_desc_info, const char *comp_name, const char *comp_semver)
{
    fota_component_desc_t *comp_table = user_comp_table;
    unsigned int *num_components = &num_user_components;

    FOTA_ASSERT(comp_name);
    FOTA_ASSERT(!(comp_desc_info->support_delta && (!comp_desc_info->curr_fw_get_digest || !comp_desc_info->curr_fw_read)));

#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
    if (comp_name[0] == '%') {
        comp_table = malloc((num_int_components + 1) * sizeof(fota_component_desc_t));
        FOTA_ASSERT(comp_table);
        memcpy(comp_table, int_comp_table, num_int_components * sizeof(fota_component_desc_t));
        free(int_comp_table);
        int_comp_table = comp_table;
        num_components = &num_int_components;
    } else {
        FOTA_ASSERT(*num_components < FOTA_NUM_COMPONENTS);
    }
#else
    FOTA_ASSERT(*num_components < FOTA_NUM_COMPONENTS);
#endif

    memcpy(&comp_table[*num_components].desc_info, comp_desc_info, sizeof(*comp_desc_info));
    strncpy(comp_table[*num_components].name, comp_name, FOTA_COMPONENT_MAX_NAME_SIZE - 1);
    fota_component_version_semver_to_int(comp_semver, &comp_table[*num_components].version);

    (*num_components)++;
    return FOTA_STATUS_SUCCESS;
}

unsigned int fota_component_num_components(void)
{
    return num_user_components;
}

void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc)
{
    fota_component_desc_t *comp_table = user_comp_table;
    unsigned int num_components = num_user_components;

#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
    comp_id_translate(&comp_id, &comp_table, &num_components);
#endif

    FOTA_ASSERT(comp_id < num_components);
    *comp_desc = &comp_table[comp_id];
}

void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version)
{
    fota_component_desc_t *comp_table = user_comp_table;
    unsigned int num_components = num_user_components;

#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
    comp_id_translate(&comp_id, &comp_table, &num_components);
#endif
    FOTA_ASSERT(comp_id < num_components);
    *version = comp_table[comp_id].version;
}

void fota_component_set_curr_version(unsigned int comp_id, fota_component_version_t version)
{
    fota_component_desc_t *comp_table = user_comp_table;
    unsigned int num_components = num_user_components;

#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
    comp_id_translate(&comp_id, &comp_table, &num_components);
#endif
    FOTA_ASSERT(comp_id < num_components);
    comp_table[comp_id].version = version;
}

int fota_component_name_to_id(const char *name, unsigned int *comp_id)
{
    fota_component_desc_t *comp_table = user_comp_table;
    unsigned int num_components = num_user_components;

#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
    if (name[0] == '%') {
        comp_table = int_comp_table;
        num_components = num_int_components;
    }
#endif

    int i = num_components;

    // One or more components
    do {
        if (!strncmp(name, comp_table[num_components - i].name, FOTA_COMPONENT_MAX_NAME_SIZE)) {
            *comp_id = num_components - i;
#ifdef FOTA_INTERNAL_COMPONENTS_SUPPORT
            if (name[0] == '%') {
                *comp_id |= INT_COMP_ID_FLAG;
            }
#endif
            return FOTA_STATUS_SUCCESS;
        }
    } while (--i);

    return FOTA_STATUS_NOT_FOUND;
}

int fota_component_version_int_to_semver(fota_component_version_t version, char *sem_ver)
{
    uint32_t major, minor, split;
    uint64_t full_mask = 0xFFFFFFFFFFFFFFFFULL;
    int ret = FOTA_STATUS_SUCCESS;
    char *tmp = sem_ver;

    if (version & FOTA_COMPONENT_SEMVER_BIT) {
        split = version & ~(full_mask << SPLIT_NUM_BITS);
        minor = (version & ~(full_mask << (SPLIT_NUM_BITS + MINOR_NUM_BITS))) >> SPLIT_NUM_BITS;
        major = (version & ~FOTA_COMPONENT_SEMVER_BIT) >> (SPLIT_NUM_BITS + MINOR_NUM_BITS);

        if ((major > MAX_VER) || (minor > MAX_VER) || (split > MAX_VER)) {
            ret = FOTA_STATUS_INTERNAL_ERROR;
        }

        //These are only needed if above check fails (unittests only)
        split = MIN(split, MAX_VER);
        minor = MIN(minor, MAX_VER);
        major = MIN(major, MAX_VER);

    } else {
        // assume client migrate to fota and the version represent v1 timestamp
        // set default SemVer to 0.0.0
        split = 0;
        minor = 0;
        major = 0;
    }

    //ouput is "major.minor.split\0"
    tmp = append_number_to_string(tmp, major, '.');
    tmp = append_number_to_string(tmp, minor, '.');
    tmp = append_number_to_string(tmp, split, '\0');
    return ret;
}

int fota_component_version_semver_to_int(const char *sem_ver, fota_component_version_t *version)
{
    // This better use signed strtol() instead of strtoul() as it is already used by other code
    // and there is no need to add more dependencies here. That change saves ~120B.
    long major, minor, split;
    char *endptr;
    int ret = FOTA_STATUS_SUCCESS;

    major = strtol(sem_ver, &endptr, 10);
    minor = strtol(endptr + 1, &endptr, 10);
    split = strtol(endptr + 1, &endptr, 10);
    FOTA_DBG_ASSERT((endptr - sem_ver) <= FOTA_COMPONENT_MAX_SEMVER_STR_SIZE);

    if ((major < 0) || (major > MAX_VER) ||
            (minor < 0) || (minor > MAX_VER) ||
            (split < 0) || (split > MAX_VER)) {
        ret = FOTA_STATUS_INTERNAL_ERROR;

        // Unfortunately not all call sites of this handle the error, so this might as well
        // give stable output on error path too.
        *version = 0;
    } else {

        split = MIN(split, MAX_VER);
        minor = MIN(minor, MAX_VER);
        major = MIN(major, MAX_VER);

        *version =  FOTA_COMPONENT_SEMVER_BIT |
                    ((uint64_t) split) | 
                    ((uint64_t) minor << SPLIT_NUM_BITS) | 
                    ((uint64_t) major << (SPLIT_NUM_BITS + MINOR_NUM_BITS));
    }
    return ret;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
