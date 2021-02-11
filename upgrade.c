// ----------------------------------------------------------------------------
// Copyright 2019-2021 ARM Ltd.
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

#include "fota/fota_block_device.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_crypto.h"
#include "fota/fota_platform.h"
#include "fota/fota_header_info.h"
#include "fota/fota_candidate.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"
#include "flash_api.h"
#include "mbed_trace.h"
#include "platform/mbed_application.h"
#include "platform/mbed_toolchain.h"
#include "platform/mbed_power_mgmt.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "fota_device_key.h"

#include <stdlib.h>

flash_t flash_obj;

size_t bd_read_size;
size_t bd_prog_size;
uint32_t flash_page_size;

#define FLASH_READ_BUFFER_SIZE 1024
#define INTERNAL_HEADER_SIZE offsetof(fota_header_info_t, internal_header_barrier)

fota_header_info_t installed_header = {0};
volatile bool check_version = true;

static int erase_flash(uint32_t start_addr, uint32_t end_addr)
{
    uint32_t aligned_start_addr = FOTA_ALIGN_DOWN(start_addr, flash_get_sector_size(&flash_obj, start_addr));
    uint32_t aligned_end_addr = FOTA_ALIGN_UP(end_addr, flash_get_sector_size(&flash_obj, end_addr));

    if (aligned_start_addr != start_addr) {
        pr_warning("WARNING: header address is not aligned to a sector boundary");
    }

    uint32_t erase_addr = aligned_start_addr;
    while (erase_addr < aligned_end_addr) {
        uint32_t erase_size = flash_get_sector_size(&flash_obj, erase_addr);
        if (flash_erase_sector(&flash_obj, erase_addr) != 0) {
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
        erase_addr += erase_size;
    }

    return FOTA_STATUS_SUCCESS;
}

static int init_storage(void)
{
    // This will do nothing in charger and set up the DFRD BD in holder
    int ret = fota_platform_start_update_hook(FOTA_COMPONENT_MAIN_COMPONENT_NAME);
    if (ret) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    ret = fota_bd_init();
    if (ret) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    ret = fota_bd_get_read_size(&bd_read_size);
    if (ret) {
        return ret;
    }

    ret = fota_bd_get_program_size(&bd_prog_size);
    if (ret) {
        return ret;
    }

    return FOTA_STATUS_SUCCESS;
}

static int deinit_storage(void)
{
    fota_bd_deinit();
    flash_free(&flash_obj);
    fota_platform_finish_update_hook(FOTA_COMPONENT_MAIN_COMPONENT_NAME);

    return FOTA_STATUS_SUCCESS;
}

static int install_start(fota_candidate_iterate_callback_info *info)
{
    int ret;
    const fota_header_info_t *cand_header = info->header_info;
    size_t volatile loop_check;

    FOTA_FI_SAFE_COND((!check_version ||
                        ((installed_header.magic == FOTA_FW_HEADER_MAGIC) &&
                        (!fota_fi_memcmp(installed_header.digest, cand_header->precursor,
                        FOTA_CRYPTO_HASH_SIZE, &loop_check) &&
                        (loop_check == FOTA_CRYPTO_HASH_SIZE)))),
                        FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH, "Precursor doesn't match installed digest");

    FOTA_FI_SAFE_COND((!check_version ||
                        ((installed_header.magic == FOTA_FW_HEADER_MAGIC) &&
                        (installed_header.version < cand_header->version))),
                        FOTA_STATUS_MANIFEST_VERSION_REJECTED,
                        "Candidate version is not newer than installed");

    pr_info("Candidate verification successful. Starting installation to flash...");

    ret = erase_flash(MBED_CONF_MBED_BOOTLOADER_APPLICATION_HEADER_ADDRESS,
                      MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS + cand_header->fw_size);
    if (ret != FOTA_STATUS_SUCCESS) {
        pr_error("Erase flash failed. ret code %d", ret);
        return ret;
    }

    return FOTA_STATUS_SUCCESS;

fail:
    return ret;
}

static int install_program_fragment(fota_candidate_iterate_callback_info *info)
{
    int ret;
    static const uint32_t  print_range_percent = 5;

    uint32_t progress = (info->frag_pos + info->frag_size) * 100 / info->header_info->fw_size;
    uint32_t prev_progress = info->frag_pos * 100 / info->header_info->fw_size;

    if (info->frag_pos == 0 || ((progress / print_range_percent) > (prev_progress / print_range_percent))) {
        pr_cmd("Flashing. %" PRIu32 "%c complete", progress, '%');
    }

    // Would need to check that info->frag_buf is aligned to 8 bytes, as HAL flash driver won't accept it
    // otherwise. We have preliminary knowledge that it's like that here, so we slip this check.
    ret = flash_program_page(&flash_obj, MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS + info->frag_pos,
                             info->frag_buf, info->frag_size);
    if (ret) {
        pr_error("flash program failed");
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    if (memcmp((uint8_t *)MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS + info->frag_pos,
               info->frag_buf, info->frag_size)) {
        pr_error("flash readback verification failed");
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    return FOTA_STATUS_SUCCESS;
}

static int install_finish(const fota_candidate_iterate_callback_info *info)
{
    int ret;
    uint32_t header_buf_size = FOTA_ALIGN_UP(INTERNAL_HEADER_SIZE, flash_page_size);
    uint8_t *header_buf = (uint8_t *) malloc(header_buf_size);
    if (!header_buf) {
        pr_error("Unable to allocate header");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    fota_header_info_t *header = (fota_header_info_t *) header_buf;

    memset(header_buf, 0, header_buf_size);
    memcpy(header, info->header_info, INTERNAL_HEADER_SIZE);

    // Flash new FW header
    ret = flash_program_page(&flash_obj, MBED_CONF_MBED_BOOTLOADER_APPLICATION_HEADER_ADDRESS,
                             header_buf, header_buf_size);
    if (ret) {
        pr_error("Programming header failed");
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    return FOTA_STATUS_SUCCESS;
}

static int install_iterate_handler(fota_candidate_iterate_callback_info *info)
{

    switch (info->status) {
        case FOTA_CANDIDATE_ITERATE_START:
            return install_start(info);
        case FOTA_CANDIDATE_ITERATE_FRAGMENT:
            return install_program_fragment(info);
            break;
        case FOTA_CANDIDATE_ITERATE_FINISH:
            return install_finish(info);
            break;
        default:
            return FOTA_STATUS_INTERNAL_ERROR;
    }
    return 0;
}

int fota_nvm_fw_encryption_key_get(uint8_t buffer[FOTA_ENCRYPT_KEY_SIZE])
{
    return fota_get_device_key_128bit(buffer, FOTA_ENCRYPT_KEY_SIZE);        
}

static int check_and_install_update()
{
    int ret = FOTA_STATUS_NOT_FOUND;
    bool validate = true;    
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    bool force_encrypt = true;
#else
    bool force_encrypt = false;    
#endif // #if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)

    ret = init_storage();
    if (ret != FOTA_STATUS_SUCCESS) {
        pr_error("Storage initialization failed!");
        return ret;
    }

    flash_page_size = flash_get_page_size(&flash_obj);

    ret = fota_candidate_iterate_image(validate, force_encrypt, FOTA_COMPONENT_MAIN_COMPONENT_NAME, flash_page_size,
                                       install_iterate_handler);
    if (ret) {                                       
        if(ret == FOTA_STATUS_NOT_FOUND) {
            deinit_storage();
            pr_info("Candidate not found");
            return ret;
        }
        goto end;
    }

    pr_cmd("Installation finished.");

end:
    deinit_storage();
    pr_info("check_and_install_update %d.", ret);
    return ret;
}

static int read_installed_fw_header()
{
    pr_debug("HEADER ADDR=0x%08X", MBED_CONF_MBED_BOOTLOADER_APPLICATION_HEADER_ADDRESS);
    memset(&installed_header, 0, sizeof(installed_header));
    int ret = flash_read(&flash_obj,
                         MBED_CONF_MBED_BOOTLOADER_APPLICATION_HEADER_ADDRESS,
                         (uint8_t *) &installed_header, INTERNAL_HEADER_SIZE);

    if (ret) {
        return FOTA_STATUS_STORAGE_READ_FAILED;
    }

    if (installed_header.magic != FOTA_FW_HEADER_MAGIC) {
        memset(&installed_header, 0, sizeof(installed_header));
        return FOTA_STATUS_NOT_FOUND;
    }

    return FOTA_STATUS_SUCCESS;
}

static int validate_installed_fw()
{
    fota_hash_context_t *digest_ctx;
    int tmp_ret = FOTA_STATUS_INTERNAL_ERROR;
    uint8_t digest[FOTA_CRYPTO_HASH_SIZE] = { 0 };
    int ret = FOTA_STATUS_INTERNAL_ERROR;
    uint32_t addr = MBED_CONF_MBED_BOOTLOADER_APPLICATION_START_ADDRESS;
    
    pr_info("Validating image on flash...");

    ret = read_installed_fw_header();
    if (ret) {
        pr_error("failed read_installed_fw_header...");
        return ret;
    }

    uint32_t size = installed_header.fw_size;

    pr_debug("FW addr=0x%08X size=0x%X", addr, size);
    tmp_ret = fota_hash_start(&digest_ctx);
    if (tmp_ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }

    fota_hash_update(digest_ctx, (const uint8_t *) addr, size);
    if (tmp_ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }

    tmp_ret = fota_hash_result(digest_ctx, digest);
    if (tmp_ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }
    
    pr_debug("Validating image on flash finished");

#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    sig_verify_status = fota_verify_signature_prehashed(
                            digest,
                            installed_header.signature,
                            FOTA_IMAGE_RAW_SIGNATURE_SIZE
                        );
    FOTA_FI_SAFE_COND(
        (sig_verify_status == FOTA_STATUS_SUCCESS),
        FOTA_STATUS_MANIFEST_SIGNATURE_INVALID,
        "FW image is not authentic"
    );
#else
    pr_debug("check hash");
    FOTA_FI_SAFE_MEMCMP(digest, installed_header.digest, FOTA_CRYPTO_HASH_SIZE,
                        FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED, "Hash mismatch!");

#endif
    pr_debug("validate success");
    ret = FOTA_STATUS_SUCCESS;
fail:
    fota_hash_finish(&digest_ctx);

    return ret;
}

MBED_NORETURN void mbed_die(void)
{
    while (true) {
        __WFI();
    }
}

int main(void)
{
    bool is_new_firmware = false;
    pr_cmd("Bootloader build at: " __DATE__ " " __TIME__);
    volatile int ret = FOTA_STATUS_INTERNAL_ERROR, installed_fw_status = FOTA_STATUS_INTERNAL_ERROR;
    volatile int install_update_status = FOTA_STATUS_INTERNAL_ERROR;
#if MBED_BOOTLOADER_RESET_ON_PANIC
    bool reset = true;
#else
    bool reset = false;
#endif

#if (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_PRINTF)
    char semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE];
#endif

    if (flash_init(&flash_obj) != 0) {
        pr_error("Flash initialization failed!");
        goto fail;
    }

    pr_info("Searching for candidate image...");

    do {
        read_installed_fw_header();
        // First try check and install with version checks on (set to true by default)
        install_update_status = check_and_install_update();
        if (install_update_status == FOTA_STATUS_NOT_FOUND) {
            break;
        }

        // Always reset after any failure in install firmware flow.
        // Guarantees that glitches in installation are recovered next time.
        reset = true;

        if (install_update_status == FOTA_STATUS_SUCCESS) {
            is_new_firmware = true;
            break;
        }

        // Unsuccessful installation. Might have damaged the installed firmware.
        // Check first if this is indeed the case. If so, reinstall update, now with version checks off.

        installed_fw_status = validate_installed_fw();
        if (installed_fw_status == FOTA_STATUS_SUCCESS) {
            break;
        }

        check_version = false;
        install_update_status = check_and_install_update();
        if (install_update_status == FOTA_STATUS_SUCCESS) {
            is_new_firmware = true;
        }

    } while (0);

    // Prevent FI on hash digest (so it won't be equal to 0 in both places)
#if FOTA_FI_MITIGATION_ENABLE
    mbedtls_platform_random_delay();
#endif

    installed_fw_status = validate_installed_fw();
    FOTA_FI_SAFE_COND(installed_fw_status == FOTA_STATUS_SUCCESS,
                      installed_fw_status, "Validating installed firmware failed");
    if (is_new_firmware && installed_fw_status == FOTA_STATUS_SUCCESS ) {
        pr_info("New active firmware is valid\r\n");
    }

#if (MBED_CONF_MBED_BOOTLOADER_TRACE == USE_PRINTF)
    ret = fota_component_version_int_to_semver(installed_header.version, semver);
    if (ret) {
        pr_cmd("Current FW version is %" PRIu64, installed_header.version);
    } else {
        pr_cmd("Current FW version is %s", semver);
    }
#endif
    pr_cmd("All clear. Jumping to application (at address 0x%x).\n\n\n",
            MBED_CONF_MBED_BOOTLOADER_APPLICATION_JUMP_ADDRESS);

    mbed_start_application(MBED_CONF_MBED_BOOTLOADER_APPLICATION_JUMP_ADDRESS);

fail:
    pr_error("PANIC!");
    if (reset) {
        system_reset();        
    } else {
       mbed_die();
    }        
    return 0;
}
