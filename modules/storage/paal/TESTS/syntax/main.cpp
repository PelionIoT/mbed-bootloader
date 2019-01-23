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

#include <greentea-client/test_env.h>
#include <utest/utest.h>
#include <unity/unity.h>

#include "update-client-paal/arm_uc_paal_update_api.h"

using namespace utest::v1;

#if defined(TARGET_LIKE_POSIX)
#include <unistd.h>
#define __WFI() usleep(100)
#endif

control_t syntax_check()
{
    ARM_UC_PAAL_UPDATE test = { 0 };

    return CaseNext;
}

Case cases[] = {
    Case("syntax_check", syntax_check),
};

utest::v1::status_t greentea_setup(const size_t number_of_cases)
{
#if defined(TARGET_LIKE_MBED)
    GREENTEA_SETUP(60, "default_auto");
#endif
    return greentea_test_setup_handler(number_of_cases);
}

Specification specification(greentea_setup, cases);

#if defined(TARGET_LIKE_MBED)
int main()
#elif defined(TARGET_LIKE_POSIX)
void app_start(int argc __unused, char **argv __unused)
#endif
{
    // Run the test specification
    Harness::run(specification);
}
