/* mbed Microcontroller Library
 * Copyright (c) 2020 ARM Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "boot_nvm_storage.h"

#if (MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == PDBSTORE)
#if !defined(FOTA_USE_EXTERNAL_FW_KEY)

#if MBED_CONF_PDBSTORE_SIM_ENABLED
#include "pdbstore_sim.h"
#elif MBED_CONF_PDBSTORE_EEPROM_ENABLED
#include "pdbstore_eeprom.h"
#endif
#include "mbed_trace.h"

int nvm_storage_init()
{
    int ret;
    // TODO: Use real driver in actual board
#if MBED_CONF_PDBSTORE_SIM_ENABLED
    ret = pdbstore_sim_init();
#elif MBED_CONF_PDBSTORE_EEPROM_ENABLED
    ret = pdbstore_eeprom_init();
#else
    ret = 0;
#endif
    if (ret) {
        pr_error("PDBStore initialization failed!");
    }
    return ret;
}

int nvm_storage_deinit()
{
#if MBED_CONF_PDBSTORE_SIM_ENABLED
    return pdbstore_sim_deinit();
#elif MBED_CONF_PDBSTORE_EEPROM_ENABLED
    return pdbstore_eeprom_deinit();
#else
    return 0;
#endif
}
#else // !defined(FOTA_USE_EXTERNAL_FW_KEY)
inline int nvm_storage_init()
{
    return 0;
}
inline int nvm_storage_deinit()
{
    return 0;
}
#endif //!deined(FOTA_USE_EXTERNAL_FW_KEY)
#endif // MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == PDBSTORE
