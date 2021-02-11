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

#ifndef __FOTA_CRYPTO_DEFS_H_
#define __FOTA_CRYPTO_DEFS_H_

#include "fota/fota_base.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FOTA_ENCRYPT_KEY_SIZE 16 /*< AES-128 key size in bytes */

#define FOTA_ENCRYPT_TAG_SIZE 8 /*< AES-CCM tag size in bytes */

#define FOTA_CRYPTO_HASH_SIZE  32  /*< SHA256 digest size in bytes*/

#define FOTA_UPDATE_RAW_PUBLIC_KEY_SIZE 65  // compression byte  | r | s
#define FOTA_IMAGE_RAW_SIGNATURE_SIZE 64  // raw signature

#ifdef __cplusplus
}
#endif

#endif // __FOTA_CRYPTO_DEFS_H_
