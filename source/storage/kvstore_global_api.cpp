/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "boot_nvm_storage.h"

#if ((MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == KVSTORE) && !defined(FOTA_USE_EXTERNAL_FW_KEY))

#include "kvstore_global_api.h"
#include "mbed_error.h"
#include "mbed_trace.h"
#include "TDBStore.h"
#include "FlashIAPBlockDevice.h"

bool initialized = false;
FlashIAPBlockDevice *bd;
mbed::TDBStore *tdb = 0;

#ifdef __cplusplus
extern "C" {
#endif

int nvm_storage_init()
{
    int ret;
    if (initialized) {
        return 0;
    }

    bd = new FlashIAPBlockDevice(MBED_CONF_STORAGE_TDB_INTERNAL_INTERNAL_BASE_ADDRESS, MBED_CONF_STORAGE_TDB_INTERNAL_INTERNAL_SIZE);
    if (!bd) {
        pr_error("Unable to allocate FlashIAPBlockDevice");
        ret = -1;
        goto fail;
    }

    ret = bd->init();
    if (ret) {
        pr_error("Flash bd init failed");
        goto fail;
    }

    tdb = new mbed::TDBStore(bd);
    if (!tdb) {
        pr_info("tUnable to allocate TDBStore");
        ret = -1;
        goto fail;
    }

    ret = tdb->init();
    if (!tdb) {
        pr_error("TDBStore init failed");
        ret = -1;
        goto fail;
    }

    initialized = true;
    return 0;

fail:
    delete tdb;
    delete bd;
    return ret;
}

int nvm_storage_deinit()
{
    delete tdb;
    delete bd;
    initialized = false;
    return 0;
}

int kv_set(const char *full_name_key, const void *buffer, size_t size, uint32_t create_flags)
{
    return MBED_ERROR_UNSUPPORTED;
}

int kv_get(const char *full_name_key, void *buffer, size_t buffer_size, size_t *actual_size)
{
    if (!initialized) {
        return -1;
    }
    const char *key = strrchr(full_name_key, '/');
    if (key) {
        key++;
    } else {
        key = full_name_key;
    }
    int ret = tdb->get(key, buffer, buffer_size, actual_size);
    return ret;
}

int kv_get_info(const char *full_name_key, kv_info_t *info)
{
    return MBED_ERROR_UNSUPPORTED;
}

int kv_remove(const char *full_name_key)
{
    return MBED_ERROR_UNSUPPORTED;
}

int kv_iterator_open(kv_iterator_t *it, const char *full_prefix)
{
    return MBED_ERROR_UNSUPPORTED;
}

int kv_iterator_next(kv_iterator_t it, char *key, size_t key_size)
{
    return MBED_ERROR_UNSUPPORTED;
}

int kv_iterator_close(kv_iterator_t it)
{
    return MBED_ERROR_UNSUPPORTED;
}

int kv_reset(const char *kvstore_name)
{
    return MBED_ERROR_UNSUPPORTED;
}

MBED_WEAK int kv_deinit_storage_config()
{
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif // ((MBED_CONF_MBED_BOOTLOADER_STORAGE_TYPE == KVSTORE) && !defined(FOTA_USE_EXTERNAL_FW_KEY)
