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

#ifndef PAL_HEADER_SOTP_FS
#define PAL_HEADER_SOTP_FS

#define PAL_USE_HW_ROT 0
#define PAL_USE_HW_RTC 0
#define PAL_USE_HW_TRNG 1
#define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM 0
#define PAL_USE_INTERNAL_FLASH 1
#define PAL_USE_SECURE_TIME 1

#include "mbedOS_default.h"

#endif //PAL_HEADER_SOTP_FS
