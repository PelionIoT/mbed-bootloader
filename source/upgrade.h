// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#include <stdint.h>

#ifndef MAX_COPY_RETRIES
#define MAX_COPY_RETRIES 1
#endif

extern uint64_t *heapVersion;
extern uint8_t *bootCounter;

/**
 * Find suitable update candidate and copy firmware into active region
 * @return true if the active firmware region is valid.
 */
bool upgradeApplicationFromStorage(void);
