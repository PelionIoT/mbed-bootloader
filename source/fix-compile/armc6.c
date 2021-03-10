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

#ifdef __ARMCC_VERSION

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

// Some fuction we should add a stub in case we compile with ARMC6
// Feature or ARM compilers. You must satisfy the dependencies of all files, before linker checks if the function is actually needed.

#include "fota/fota_crypto.h"

int fota_verify_signature_prehashed(
      const uint8_t *data_digest,
      const uint8_t *sig, size_t sig_len
)
{
      return -1;
}
#endif 

#endif // __ARMCC_VERSION
