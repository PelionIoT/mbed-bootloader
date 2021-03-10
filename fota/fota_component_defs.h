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

#ifndef __FOTA_COMPONENT_DEFS_H_
#define __FOTA_COMPONENT_DEFS_H_

#include "fota/fota_base.h"

#if defined(TARGET_LIKE_LINUX)
#if !defined(FOTA_NUM_COMPONENTS)
#define FOTA_NUM_COMPONENTS 5
#endif
#endif

#define FOTA_COMPONENT_SEMVER_BIT         ((uint64_t)1 << 55)
#define FOTA_COMPONENT_MAX_NAME_SIZE       9
#define FOTA_COMPONENT_MAX_SEMVER_STR_SIZE 12

#define FOTA_COMPONENT_MAIN_COMP_NUM       0
#define FOTA_COMPONENT_MAIN_COMPONENT_NAME "MAIN"

typedef uint64_t fota_component_version_t;

#endif // __FOTA_COMPONENT_DEFS_H_
