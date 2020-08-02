// Copyright 2018-2019 ARM Ltd.
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

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota.h"
#include "fota/fota_status.h"
#include "fota/fota_internal.h"
#include "fota/fota_manifest.h"
#include "fota/fota_source.h"
#include "fota/fota_delta.h"
#include "fota/fota_app_ifs.h"
#include "fota/fota_platform.h"
#include "fota/fota_nvm.h"
#include "fota/fota_block_device.h"
#include "fota/fota_crypto.h"
#include "fota/fota_header_info.h"
#include "fota/fota_curr_fw.h"
#include "fota/fota_event_handler.h"
#include "fota/fota_candidate.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include <stdlib.h>
#include <inttypes.h>

#ifdef __MBED__
#include "mbed_power_mgmt.h"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME) && !FOTA_HEADER_HAS_CANDIDATE_READY
#error Full resume feature is not supported for legacy/external images
#endif

#define MAIN_COMP_NUM 0

static fota_context_t *fota_ctx = NULL;

static int handle_fw_fragment(uint8_t *buf, size_t size, bool last);
static void handle_manifest(uint8_t *manifest_buf, size_t manifest_size, bool is_resume);
static void on_reboot(void);
static int finalize_update(void);
static void fota_on_install_authorize(bool defer);

static bool initialized = false;

fota_context_t *fota_get_context(void)
{
    return fota_ctx;
}

static void free_context_buffers(void)
{
    if (!fota_ctx) {
        return;
    }
    free(fota_ctx->fw_info);
    fota_ctx->fw_info = NULL;
    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;

#if !defined(FOTA_DISABLE_DELTA)
    free(fota_ctx->delta_buf);
    fota_ctx->delta_buf = NULL;
    if (fota_ctx->delta_ctx) {
        fota_delta_finalize(&fota_ctx->delta_ctx);
    }
#endif  // !defined(FOTA_DISABLE_DELTA)

    if (fota_ctx->enc_ctx) {
        fota_encrypt_finalize(&fota_ctx->enc_ctx);
    }
    if (fota_ctx->curr_fw_hash_ctx) {
        fota_hash_finish(&fota_ctx->curr_fw_hash_ctx);
    }
}

static void update_cleanup(void)
{
    free_context_buffers();
    free(fota_ctx);
    fota_ctx = NULL;
}

#define abort_update(ret, msg) do { \
    FOTA_TRACE_ERROR("Update aborted: %s", msg); \
    abort_update__(ret); \
} while(0)
static void abort_update__(int ret)
{
    int upd_res;
    bool do_terminate_update = true;

    if (!fota_is_active_update()) {
        return;
    }

    if (ret == FOTA_STATUS_FAIL_UPDATE_STATE ||
            ret == FOTA_STATUS_UPDATE_DEFERRED) {
        do_terminate_update = false;  // recoverable error, will trigger resume
    } else {
        upd_res = -1 * ret; // return to cloud
    }

    if (do_terminate_update) {
        fota_source_report_update_result(upd_res);
        fota_source_report_state(FOTA_SOURCE_STATE_IDLE, NULL, NULL);
        fota_nvm_manifest_delete();
    } else {
        fota_source_report_state(FOTA_SOURCE_STATE_PROCESSING_MANIFEST, NULL, NULL);
    }

    fota_nvm_fw_encryption_key_delete();

    const fota_component_desc_t *comp_desc;
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);
    fota_platform_abort_update_hook(comp_desc->name);
    fota_app_on_complete(ret); //notify application
    update_cleanup();
}

static void on_state_set_failure(void)
{
    abort_update(FOTA_STATUS_FAIL_UPDATE_STATE, "Failed to deliver FOTA state");
}

bool fota_is_active_update(void)
{
    return (fota_ctx != NULL);
}

int fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state)
{
    size_t manifest_size;
    uint8_t *manifest = malloc(FOTA_MANIFEST_MAX_SIZE);
    if (!manifest) {
        FOTA_TRACE_ERROR("FOTA manifest - allocation failed");
        *fota_state = FOTA_STATE_INVALID;
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    memset(manifest, 0, FOTA_MANIFEST_MAX_SIZE);
    int ret = fota_nvm_manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (ret) { //  cannot find saved manifest - ready to start an update
        *fota_state = FOTA_STATE_IDLE;
        goto CLEANUP;
    }
    // manifest always saved with MAX size memcmp should be done on input size
    if ((size <= manifest_size) && (0 == memcmp(manifest, data, size))) {
        // notify FOTA already handles same manifest
        *fota_state = FOTA_STATE_DOWNLOADING;
        goto CLEANUP;
    }
    // fota is busy - different update is active
    *fota_state = FOTA_STATE_INVALID;

CLEANUP:
    free(manifest);
    return FOTA_STATUS_SUCCESS;
}

static inline void fota_dev_init(void)
{
    int ret;

#if defined(MBED_CLOUD_DEV_UPDATE_ID) && !defined(FOTA_USE_EXTERNAL_IDS)
    ret = fota_nvm_update_class_id_set();
    FOTA_ASSERT(!ret);

    ret = fota_nvm_update_vendor_id_set();
    FOTA_ASSERT(!ret);
#endif

#if defined(FOTA_USE_UPDATE_X509) && defined(MBED_CLOUD_DEV_UPDATE_CERT) && !defined(FOTA_USE_EXTERNAL_CERT)
    ret = fota_nvm_update_cert_set();
    FOTA_ASSERT(!ret);
#endif

#if defined(FOTA_USE_UPDATE_RAW_PUBLIC_KEY) && defined(MBED_CLOUD_DEV_UPDATE_RAW_PUBLIC_KEY) && !defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY)
    ret = fota_nvm_set_update_public_key();
    FOTA_ASSERT(!ret);
#endif

    (void)ret;  // fix unused variable warning in production
}

#if (FOTA_NUM_COMPONENTS > 1)
int fota_install_verify(const fota_component_desc_t *comp_desc, unsigned int comp_id, uint64_t new_ver)
{
    int ret = FOTA_STATUS_SUCCESS;
    if (comp_desc->component_post_install_cb) {
        // callback to check if installed succeded.
        char nvm_semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = {0};
        ret = fota_component_version_int_to_semver(new_ver, nvm_semver);
        if (ret) {
            FOTA_TRACE_ERROR("Failed to convert to sem version %d", ret);
            return ret;
        }

        ret = comp_desc->component_post_install_cb(nvm_semver);
        if (ret) {
            FOTA_TRACE_ERROR("Failed to verify installation %d", ret);
            return ret;
        }
    }

    // Successful finish actions
    fota_component_set_curr_version(comp_id, new_ver);
    // Not saving version for the MAIN component
    fota_nvm_comp_version_set(comp_desc->name, new_ver);
    return ret;
}
#endif // FOTA_NUM_COMPONENTS > 1

int fota_handle_post_install()
{
    int ret = FOTA_STATUS_SUCCESS;
#if (FOTA_NUM_COMPONENTS > 1)
    uint32_t bd_read_size;
    uint32_t bd_prog_size;
    unsigned int comp_id;
    uint32_t addr;
    fota_candidate_ready_header_t comp_header;
    const fota_component_desc_t *comp_desc;
    fota_header_info_t header;

    ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_init failed %d.", ret);
        goto fail;
    }

    ret = fota_bd_get_read_size(&bd_read_size);
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_get_read_size failed %d.", ret);
        goto fail;
    }

    ret = fota_bd_get_program_size(&bd_prog_size);
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_get_program_size failed %d.", ret);
        goto fail;
    }
    // check what component was updated to call post install callback
    // in case all done at candidate_post_install_cb, we can remove salt and report install complete
    addr = fota_candidate_get_config()->storage_start_addr;
    ret = fota_candidate_read_candidate_ready_header(&addr, bd_read_size, bd_prog_size, &comp_header);
    if (ret) {
        goto fail;
    }

    ret = fota_component_name_to_id(comp_header.comp_name, &comp_id);
    if (ret) {
        goto fail;
    }

    fota_component_get_desc(comp_id, &comp_desc);
    ret = fota_candidate_read_header(&addr, bd_read_size, bd_prog_size, &header);
    if (ret) {
        FOTA_TRACE_ERROR("failed to read candidate header %d.", ret);
        goto fail;
    }

    FOTA_TRACE_DEBUG("install verify component name %s, version %" PRIu64 " ", comp_header.comp_name, header.version);
    ret = fota_install_verify(comp_desc, comp_id, header.version);

fail:
#endif // FOTA_NUM_COMPONENTS > 1
    // in case we failed prevent infinite loop, remove FW key and report failure as post installed failed
    fota_nvm_fw_encryption_key_delete();
    return ret;
}

int fota_init(endpoint_t *in_endpoint)
{
    uint8_t vendor_id[FOTA_GUID_SIZE];
    uint8_t class_id[FOTA_GUID_SIZE];
    uint8_t *manifest = NULL;
    size_t manifest_size = 0;
    fota_source_state_e source_state = FOTA_SOURCE_STATE_IDLE;
    fota_component_desc_t main_component_desc = {0};

    uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE];
    int ret;
    bool after_upgrade = false;

    if (initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    fota_dev_init();

    FOTA_DBG_ASSERT(!fota_ctx);

    FOTA_DBG_ASSERT(in_endpoint);

    FOTA_TRACE_DEBUG("init start");

    ret = fota_random_init(NULL, 0);
    FOTA_ASSERT(!ret);

    ret = fota_nvm_get_vendor_id(vendor_id);
    FOTA_ASSERT(!ret);
    ret = fota_nvm_get_class_id(class_id);
    FOTA_ASSERT(!ret);

    fota_header_info_t header_info;
    ret = fota_curr_fw_read_header(&header_info);
    FOTA_ASSERT(!ret);

    ret = fota_event_handler_init();  // Note: must be done before fota_source
    FOTA_ASSERT(!ret);

    manifest = malloc(FOTA_MANIFEST_MAX_SIZE);
    FOTA_ASSERT(manifest);

    ret = fota_nvm_manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (!ret) {
        source_state = FOTA_SOURCE_STATE_PROCESSING_MANIFEST;
    } else {
        ret = fota_nvm_fw_encryption_key_get(fw_key);
        memset(fw_key, 0, sizeof(fw_key));
        after_upgrade = !ret;
    }

    free(manifest);

    ret = fota_source_init(
              in_endpoint,
              vendor_id, sizeof(vendor_id),
              class_id, sizeof(class_id),
              header_info.digest, sizeof(header_info.digest),
              header_info.version,
              source_state);
    FOTA_ASSERT(!ret);

    fota_component_clean();

    // register main component (should be done before platform init hook, which registers all other components).
    strcpy(main_component_desc.name, FOTA_COMPONENT_MAIN_COMPONENT_NAME);
    // "Factory" version here is what we read from main firmware header, as we don't save it to NVM.
    fota_component_version_int_to_semver(header_info.version, main_component_desc.factory_version);
    main_component_desc.need_reboot = true;
    main_component_desc.support_delta = true;
    main_component_desc.curr_fw_read = fota_curr_fw_read;
    main_component_desc.curr_fw_get_digest = fota_curr_fw_get_digest;
    ret = fota_component_add(&main_component_desc);
    FOTA_DBG_ASSERT(!ret);
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)
    // Don't show that in legacy case
    FOTA_TRACE_INFO("Registered %s component, version %s", main_component_desc.name, main_component_desc.factory_version);
#endif

    fota_component_set_curr_version(MAIN_COMP_NUM, header_info.version);

    ret = fota_source_add_component(MAIN_COMP_NUM, main_component_desc.name, main_component_desc.factory_version);
    FOTA_DBG_ASSERT(!ret);

    ret = fota_platform_init_hook(after_upgrade);
    FOTA_ASSERT(!ret);

    if (after_upgrade) {
        FOTA_TRACE_DEBUG("After upgrade, issuing post install actions");
        ret = fota_handle_post_install();
        if (ret) {
            fota_source_report_update_result(FOTA_STATUS_FW_INSTALLATION_FAILED);
        }
    }

// Code saving - only relevant if we have additional components other than the main one
#if (FOTA_NUM_COMPONENTS > 1)
    // Now we should have all components registered, report them all
    unsigned int num_comps = fota_component_num_components();
    for (unsigned int i = 1; i < num_comps; i++) {
        const fota_component_desc_t *comp_desc;
        char nvm_semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = {0};
        fota_component_version_t version;
        const char *semver;
        fota_component_get_desc(i, &comp_desc);
        ret = fota_nvm_comp_version_get(comp_desc->name, &version);
        if (!ret) {
            ret = fota_component_version_int_to_semver(version, nvm_semver);
            semver = nvm_semver;
        } else {
            ret = fota_component_version_semver_to_int(comp_desc->factory_version, &version);
            semver = comp_desc->factory_version;
        }
        FOTA_DBG_ASSERT(!ret);

        FOTA_TRACE_DEBUG("Registered %s component, version %s", comp_desc->name, semver);
        ret = fota_source_add_component(i, comp_desc->name, semver);
        FOTA_DBG_ASSERT(!ret);
        fota_component_set_curr_version(i, version);
    }
#endif // FOTA_NUM_COMPONENTS > 1

    initialized = true;
    FOTA_TRACE_DEBUG("init complete");

    return FOTA_STATUS_SUCCESS;
}

int fota_deinit(void)
{
    if (!initialized) {
        FOTA_TRACE_DEBUG("fota_deinit skipped");
        return FOTA_STATUS_SUCCESS;
    }

    FOTA_TRACE_DEBUG("fota_deinit");

    update_cleanup();
    fota_component_clean();
    fota_source_deinit();
    fota_random_deinit();
    fota_event_handler_deinit();
    fota_bd_deinit();
    initialized = false;
    return FOTA_STATUS_SUCCESS;
}

static int init_encryption(void)
{
    int ret = FOTA_STATUS_NOT_FOUND;

    uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE];

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_STARTED) {
        ret = fota_nvm_fw_encryption_key_get(fw_key);
        if (!ret) {
            FOTA_TRACE_DEBUG("Reloading saved FOTA key");
        } else {
            FOTA_TRACE_DEBUG("FOTA key not found, resetting resume state");
            // Can't continue with resume if FW key can't be reloaded
            fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
        }
    }
#endif

    if (ret) {
        if (fota_gen_random(fw_key, sizeof(fw_key))) {
            FOTA_TRACE_ERROR("Unable to generate random FW key. ret %d", ret);
            return ret;
        }

        ret = fota_nvm_fw_encryption_key_set(fw_key);
        if (ret) {
            FOTA_TRACE_ERROR("Unable to set FW key. ret %d", ret);
            return ret;
        }

        FOTA_TRACE_DEBUG("New FOTA key saved");
    }


#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    ret = fota_encrypt_decrypt_start(&fota_ctx->enc_ctx, fw_key, sizeof(fw_key));
    memset(fw_key, 0, sizeof(fw_key));
    if (ret) {
        FOTA_TRACE_ERROR("Unable to start encryption engine. ret %d", ret);
        return ret;
    }
    FOTA_TRACE_DEBUG("FOTA encryption engine initialized");
#endif
    return FOTA_STATUS_SUCCESS;
}

static int init_header(size_t prog_size)
{
    fota_ctx->fw_header_bd_size = fota_align_up(fota_get_header_size(), prog_size);

    // Reserve space for candidate ready header (if not legacy header version)
#if FOTA_HEADER_HAS_CANDIDATE_READY
    fota_ctx->candidate_header_size = fota_align_up(sizeof(fota_candidate_ready_header_t), prog_size);
#else
    fota_ctx->candidate_header_size = 0;
#endif

    fota_ctx->storage_addr += fota_ctx->candidate_header_size + fota_ctx->fw_header_bd_size;
    return FOTA_STATUS_SUCCESS;
}

void request_download_auth(void)
{
    FOTA_TRACE_DEBUG("Download Authorization requested");
    fota_component_version_t curr_ver;

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_ver);
    int ret = fota_app_on_download_authorization(
                  fota_ctx->auth_token,
                  fota_ctx->fw_info,
                  curr_ver
              );
    if (ret) {
        abort_update(ret, "Failed delivering Downloading authorization request");
        return;
    }
}

static void handle_manifest(uint8_t *manifest_buf, size_t manifest_size, bool is_resume)
{
    int ret;
    int manifest_save_ret = FOTA_STATUS_INTERNAL_ERROR;
    const fota_component_desc_t *comp_desc;
    fota_component_version_t curr_fw_version;
    uint8_t curr_fw_digest[FOTA_CRYPTO_HASH_SIZE] = {0};

    if (fota_ctx) {
        ret = FOTA_STATUS_MANIFEST_ALREADY_IN_PROCESS;
        FOTA_TRACE_ERROR("Manifest already in progress.");
        goto fail;
    }

    fota_ctx = (fota_context_t *)malloc(sizeof(*fota_ctx));
    if (!fota_ctx) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_ERROR("Unable to allocate FOTA context.");
        goto fail;
    }
    memset(fota_ctx, 0, sizeof(*fota_ctx));

    fota_ctx->fw_info = (manifest_firmware_info_t *) malloc(sizeof(manifest_firmware_info_t));
    if (!fota_ctx->fw_info) {
        FOTA_TRACE_ERROR("Unable to allocate FW info.");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto fail;
    }

    FOTA_TRACE_INFO("Firmware update initiated.");

    if (is_resume) {
        fota_ctx->resume_state = FOTA_RESUME_STATE_STARTED;
    } else {
        manifest_save_ret = fota_nvm_manifest_set(manifest_buf, manifest_size);
        if (manifest_save_ret) {
            FOTA_TRACE_ERROR("failed to persist manifest %d", manifest_save_ret);
            // ignore the error as it is not essential for good path update
        }
        fota_source_send_manifest_received_ack(); // acknowledge manifest received
        // MUST be done ONLY after persisting the manifest
    }

    ret = fota_manifest_parse(
              manifest_buf, manifest_size,
              fota_ctx->fw_info);

    // Reset manifest data, no need to keep it anymore
    memset(manifest_buf, 0, manifest_size);

    if (ret) {
        FOTA_TRACE_DEBUG("Pelion FOTA manifest rejected %d", ret);
        goto fail;
    }

    FOTA_TRACE_DEBUG("Pelion FOTA manifest is valid");

#if (FOTA_NUM_COMPONENTS == 1)
    //main component in case only one component.
    strcpy(fota_ctx->fw_info->component_name, FOTA_COMPONENT_MAIN_COMPONENT_NAME);
#endif

    ret = fota_component_name_to_id(fota_ctx->fw_info->component_name, &fota_ctx->comp_id);
    if (ret) {
        FOTA_TRACE_ERROR("Manifest addresses unknown component %s", fota_ctx->fw_info->component_name);
        ret = FOTA_STATUS_MANIFEST_UNKNOWN_COMPONENT;
        goto fail;
    }
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    if (comp_desc->curr_fw_get_digest) {
        comp_desc->curr_fw_get_digest(curr_fw_digest);
    }

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_fw_version);
    FOTA_FI_SAFE_COND(fota_ctx->fw_info->version > curr_fw_version,
                      FOTA_STATUS_MANIFEST_VERSION_REJECTED, "Manifest payload-version rejected - too old");

    FOTA_TRACE_DEBUG("get manifest : curr version %" PRIu64 ", new version %" PRIu64 " ", curr_fw_version, fota_ctx->fw_info->version);

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
#if defined(FOTA_DISABLE_DELTA)
        ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
        goto fail;
#else  // defined(FOTA_DISABLE_DELTA)
        if (!comp_desc->support_delta) {
            ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
            FOTA_TRACE_ERROR("Delta payload unsupported.");
            goto fail;
        }

        FOTA_FI_SAFE_MEMCMP(curr_fw_digest, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE,
                            FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH,
                            "Precursor digest mismatch");
#endif  // defined(FOTA_DISABLE_DELTA)
    } else {
        // If we have the current fw digest, place it in precursor for the case the installer needs it
        memcpy(fota_ctx->fw_info->precursor_digest, curr_fw_digest, FOTA_CRYPTO_HASH_SIZE);
    }

    ret = fota_gen_random((uint8_t *) &fota_ctx->auth_token, sizeof(fota_ctx->auth_token));
    if (ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }
    fota_ctx->state = FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION;

    fota_source_report_state(FOTA_SOURCE_STATE_AWAITING_DOWNLOAD_APPROVAL, request_download_auth, on_state_set_failure);

    return;

fail:
    if (manifest_save_ret == FOTA_STATUS_SUCCESS) {
        fota_nvm_manifest_delete();
    }
    // Reset buffer received from network and failed authorization/verification
    memset(manifest_buf, 0, manifest_size);
    abort_update(ret, "on manifest event failed");
}

void fota_on_manifest(uint8_t *data, size_t size)
{
    handle_manifest(data, size, /*is_resume*/ false);
}

void fota_on_reject(uint32_t token, int32_t status)
{
    FOTA_ASSERT(fota_ctx);

    FOTA_ASSERT(fota_ctx->auth_token == token);
    FOTA_DBG_ASSERT(
        (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) ||
        (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION)
    );
    fota_ctx->auth_token = 0;
    FOTA_TRACE_ERROR("Application rejected update - reason %" PRId32, status);

    if (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) {
        abort_update(FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED, "Download Authorization not granted");
    } else {
        abort_update(FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED, "Install Authorization not granted");
    }
}

void fota_on_defer(uint32_t token, int32_t status)
{
    (void)status;

    if (!fota_ctx) {
        return;  // gracefully ignore this call if update is not running
    }

    FOTA_ASSERT(fota_ctx->auth_token == token);
    fota_ctx->auth_token = 0;

    if (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        FOTA_TRACE_INFO("Installation deferred by application.");
        fota_on_install_authorize(true);
        return;
    }

    abort_update(FOTA_STATUS_UPDATE_DEFERRED, "Update deferred by application");
}

static void on_reboot(void)
{
    FOTA_TRACE_INFO("Rebooting.");

    const fota_component_desc_t *comp_desc;
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    // Reason this is here is that platform hook may cut communication with service,
    // so due to reliable report policy, this hook may not be reached.
    fota_platform_finish_update_hook(comp_desc->name);

    update_cleanup();
#ifdef __MBED__
    system_reset();
#endif
}

#if FOTA_HEADER_HAS_CANDIDATE_READY
static int write_candidate_ready(const char *comp_name)
{
    int ret;
    uint8_t *header_buf = malloc(fota_ctx->candidate_header_size);
    if (!header_buf) {
        FOTA_TRACE_ERROR("FOTA header_buf - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    memset(header_buf, 0, fota_ctx->candidate_header_size);
    fota_candidate_ready_header_t *header = (fota_candidate_ready_header_t *) header_buf;

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_ONGOING) {
        ret = fota_bd_read(header_buf, fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size);
        if (ret) {
            ret = FOTA_STATUS_STORAGE_READ_FAILED;
            goto finish;
        }
        if (header->footer == FOTA_CANDIDATE_READY_MAGIC) {
            // Already programmed - no need to do anything. Return to normal state.
            fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
            goto finish;
        }
    }
#endif

    header->magic = FOTA_CANDIDATE_READY_MAGIC;
    header->footer = FOTA_CANDIDATE_READY_MAGIC;
    strcpy(header->comp_name, comp_name);

    ret = fota_bd_program(header_buf, fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size);
    if (ret) {
        FOTA_TRACE_ERROR("candidate_ready write to storage failed %d", ret);
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        // Not really needed, just prevent warning if support resume is not configured
        goto finish;
    }

finish:

    free(header_buf);
    return ret;
}
#endif

static void install_component()
{
    unsigned int comp_id = fota_ctx->comp_id;
    const fota_component_desc_t *comp_desc;

    fota_nvm_manifest_delete();

    // reading the version before free fota_ctx
    // free fota_ctx before installation, saving RAM
#if (FOTA_NUM_COMPONENTS > 1)
    fota_component_version_t new_ver;
    new_ver = fota_ctx->fw_info->version;
#endif // FOTA_NUM_COMPONENTS > 1

    // At this point we don't need our fota context buffers any more.
    // Free them before installer starts working (to flatten memory allocation curve).
    free_context_buffers();

    fota_component_get_desc(comp_id, &comp_desc);
    FOTA_TRACE_INFO("Installing new version for component %s", comp_desc->name);

    // Code saving - only relevant if we have additional components other than the main one
#if (FOTA_NUM_COMPONENTS > 1)
    // Installer and successful finish actions apply to all components but the main one
    if (comp_id != MAIN_COMP_NUM) {
        // Run the installer using the candidate iterate service
        int ret = fota_candidate_iterate_image(true, (bool) MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT,
                                               comp_desc->name, comp_desc->install_alignment,
                                               comp_desc->candidate_iterate_cb);
        if (ret) {
            abort_update(ret, "Failed on component update");
            return;
        }

        if (!comp_desc->need_reboot) {
            ret = fota_install_verify(comp_desc, comp_id, new_ver);
            fota_nvm_fw_encryption_key_delete();
            fota_app_on_complete(ret); //notify application on after install, no reset
        }
    }
#endif // FOTA_NUM_COMPONENTS > 1

    if (comp_desc->need_reboot) {
        fota_source_report_state(FOTA_SOURCE_STATE_REBOOTING, on_reboot, on_reboot);
        return;
    }

    fota_platform_finish_update_hook(comp_desc->name);
    fota_source_report_update_result(FOTA_STATUS_FW_UPDATE_OK);
    fota_source_report_state(FOTA_SOURCE_STATE_IDLE, NULL, NULL);
    update_cleanup();
}

static int prepare_and_program_header()
{
    int ret;
    fota_header_info_t header_info = { 0 };
    size_t header_buf_actual_size = 0;
    uint8_t *header_buf = (uint8_t *) malloc(fota_ctx->fw_header_bd_size);
    if (!header_buf) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_ERROR("FOTA scratch buffer - allocation failed");
        goto fail;
    }

    memset(&header_info, 0, sizeof(header_info));
    fota_set_header_info_magic(&header_info);
    header_info.fw_size = fota_ctx->fw_info->installed_size;
    header_info.version = fota_ctx->fw_info->version;
    memcpy(header_info.digest, fota_ctx->fw_info->installed_digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(header_info.precursor, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE);
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    memcpy(header_info.signature, fota_ctx->fw_info->installed_signature, FOTA_IMAGE_RAW_SIGNATURE_SIZE);
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)

    header_info.block_size = MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE;

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    header_info.flags |= FOTA_HEADER_ENCRYPTED_FLAG;
#endif

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    header_info.flags |= FOTA_HEADER_SUPPORT_RESUME_FLAG;
#endif

    ret = fota_serialize_header(&header_info, header_buf, fota_ctx->fw_header_bd_size, &header_buf_actual_size);
    if (ret) {
        FOTA_TRACE_ERROR("serialize header failed");
        goto fail;
    }

    FOTA_DBG_ASSERT(fota_ctx->fw_header_bd_size >= header_buf_actual_size);

    ret = fota_bd_program(header_buf, fota_ctx->fw_header_offset, fota_ctx->fw_header_bd_size);
    if (ret) {
        FOTA_TRACE_ERROR("header buf write to storage failed %d", ret);
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

fail:
    free(header_buf);
    return ret;
}

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME

// Check whether a range is blank - should only be used by analyze_resume_state function
static int check_if_blank(uint32_t addr, uint32_t size, uint8_t erase_val, uint32_t *blank_start_offset)
{
    FOTA_DBG_ASSERT(fota_ctx->page_buf);
    FOTA_DBG_ASSERT(size <= fota_ctx->page_buf_size);
    FOTA_DBG_ASSERT(fota_ctx->resume_state != FOTA_RESUME_STATE_INACTIVE);

    int ret = fota_bd_read(fota_ctx->page_buf, addr, size);
    if (ret) {
        return FOTA_STATUS_STORAGE_READ_FAILED;
    }

    for (*blank_start_offset = size; *blank_start_offset > 0; --(*blank_start_offset)) {
        if (fota_ctx->page_buf[*blank_start_offset - 1] != erase_val) {
            break;
        }
    }

    return ret;
}

static int analyze_resume_state(fota_state_e *next_fota_state, uint32_t storage_available)
{
    int ret = FOTA_STATUS_SUCCESS;
    int int_erase_val = 0;
    uint8_t erase_val;
    uint32_t blank_offs;
    uint32_t num_blocks_available, num_blocks_left;
    uint32_t save_storage_addr = fota_ctx->storage_addr;
    uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE];

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT != 1)
    fota_candidate_block_checksum_t checksum = 0;
#endif

    if (fota_ctx->resume_state == FOTA_RESUME_STATE_INACTIVE) {
        return FOTA_STATUS_SUCCESS;
    }

    // Resume functionality available for full update only
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        FOTA_TRACE_DEBUG("Delta update resume is not supported");
        goto no_resume;
    }

    fota_ctx->page_buf = malloc(fota_ctx->page_buf_size);
    if (!fota_ctx->page_buf) {
        FOTA_TRACE_ERROR("Not enough memory for page_buf");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto no_resume;
    }
    fota_ctx->effective_page_buf = fota_ctx->page_buf + fota_ctx->page_buf_size - fota_ctx->effective_page_buf_size;

    ret = fota_bd_get_erase_value(&int_erase_val);
    if (ret || (int_erase_val < 0)) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto no_resume;
    }
    erase_val = (uint8_t) int_erase_val;

    // Now start analyzing candidate storage to figure resume state out

    // Note for upcoming logic in candidate ready header and further cases:
    // After checking if blank, we should read the buffer to page_buf now in order to continue with data analysis.
    // However, check_if_blank function already does that, so need to read again.

    ret = check_if_blank(fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size,
                         erase_val, &blank_offs);
    if (ret) {
        goto no_resume;
    } else if (blank_offs) {
        fota_candidate_ready_header_t *header = (fota_candidate_ready_header_t *) fota_ctx->page_buf;

        if ((header->magic != FOTA_CANDIDATE_READY_MAGIC) || (header->footer != FOTA_CANDIDATE_READY_MAGIC)) {
            // candidate header corrupt - no point resuming
            FOTA_TRACE_DEBUG("Candidate header corrupt");
            goto no_resume;
        }

        // Candidate header fully programmed - jump to install authorization
        FOTA_TRACE_DEBUG("Candidate header found. Resuming FOTA from install stage.");
        *next_fota_state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;
        // Mark resume state as ongoing, in order for later stage to know we can
        // move straight to download finish.
        fota_ctx->resume_state = FOTA_RESUME_STATE_ONGOING;
        goto finish;
    }

    // If header is blank or not fully written then no point resuming (as it's written on an early stage anyway)
    ret = check_if_blank(fota_ctx->fw_header_offset, fota_ctx->fw_header_bd_size,
                         erase_val, &blank_offs);
    if (ret || (blank_offs < fota_ctx->fw_header_bd_size)) {
        FOTA_TRACE_DEBUG("Header not programmed");
        goto no_resume;
    }

    // Now traverse candidate data

    ret = fota_nvm_fw_encryption_key_get(fw_key);
    if (ret) {
        FOTA_TRACE_DEBUG("Encryption key not found");
        goto no_resume;
    }

    num_blocks_available = storage_available / fota_ctx->page_buf_size;
    num_blocks_left = fota_align_up(fota_ctx->fw_info->payload_size, fota_ctx->effective_page_buf_size) /
                      fota_ctx->effective_page_buf_size;

    while (num_blocks_left) {

        if (num_blocks_left > num_blocks_available) {
            FOTA_TRACE_DEBUG("Not enough erased space left for resuming");
            goto no_resume;
        }

        uint32_t chunk = MIN(fota_ctx->fw_info->payload_size - fota_ctx->payload_offset, fota_ctx->effective_page_buf_size);

        ret = check_if_blank(fota_ctx->storage_addr, fota_ctx->page_buf_size, erase_val, &blank_offs);
        if (ret) {
            goto no_resume;
        }

        if (!blank_offs) {
            // If block is blank, this means we can converge to the regular downloading state.
            fota_ctx->resume_state = FOTA_RESUME_STATE_ONGOING;
            *next_fota_state = FOTA_STATE_DOWNLOADING;
            FOTA_TRACE_DEBUG("Resuming FOTA from download stage");
            goto finish;
        }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        // decrypt data with tag (at the beginning of page_buf)
        ret = fota_decrypt_data(fota_ctx->enc_ctx, fota_ctx->effective_page_buf, chunk, fota_ctx->effective_page_buf,
                                fota_ctx->page_buf);
        if (ret) {
            // Decryption failure - Skip the block
            FOTA_TRACE_DEBUG("Bad encrypted block skipped");
            goto next_block;
        }

#else
        checksum = 0;
        for (uint32_t i = 0; i < chunk; i++) {
            checksum += fota_ctx->effective_page_buf[i];
        }
        if (checksum != *(fota_candidate_block_checksum_t *) fota_ctx->page_buf) {
            // Bad checksum - Skip the block
            FOTA_TRACE_DEBUG("Bad checksum - block skipped");
            goto next_block;
        }
#endif

        // Block verified as OK - update num blocks left, hash and IV (if encrypted)
        ret = fota_hash_update(fota_ctx->curr_fw_hash_ctx, fota_ctx->effective_page_buf, chunk);
        if (ret) {
            goto no_resume;
        }
        num_blocks_left--;
        fota_ctx->payload_offset += chunk;
        fota_ctx->fw_bytes_written += chunk;

next_block:
        num_blocks_available--;
        fota_ctx->storage_addr += fota_ctx->page_buf_size;
    }

    // Got here means that the whole firmware has been written, but candidate ready header is blank.
    // This means we can converge to the regular install authorization flow.
    *next_fota_state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
    FOTA_TRACE_DEBUG("Resuming FOTA from install stage");
    goto finish;

no_resume:
    FOTA_TRACE_DEBUG("Full resume aborted, restarting FOTA");
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
    fota_ctx->storage_addr = save_storage_addr;
    fota_ctx->fw_bytes_written = 0;
    fota_ctx->payload_offset = 0;
    fota_hash_finish(&fota_ctx->curr_fw_hash_ctx);
    fota_hash_start(&fota_ctx->curr_fw_hash_ctx);
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_encryption_stream_reset(fota_ctx->enc_ctx);
#endif

finish:
    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;
    return ret;
}

#endif // MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME

static void fota_on_download_authorize()
{
    int ret;
    uint32_t prog_size;
    uint32_t storage_needed, storage_available;
    uint32_t storage_start_addr, storage_end_addr;
    uint32_t erase_size;
    const fota_component_desc_t *comp_desc;
#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    fota_state_e next_fota_state = FOTA_STATE_DOWNLOADING;
#endif

    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    ret = fota_platform_start_update_hook(comp_desc->name);
    if (ret) {
        FOTA_TRACE_ERROR("Platform start update hook failed %d", ret);
        goto fail;
    }

    ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("Unable to initialize storage %d", ret);
        ret = FOTA_STATUS_NOT_INITIALIZED;
        goto fail;
    }
    FOTA_TRACE_DEBUG("FOTA BlockDevice initialized");

    ret = fota_bd_get_program_size(&prog_size);
    if (ret) {
        FOTA_TRACE_ERROR("Get program size failed. ret %d", ret);
        goto fail;
    }

    fota_ctx->storage_addr = fota_candidate_get_config()->storage_start_addr;
    ret = init_header(prog_size);
    if (ret) {
        goto fail;
    }

    fota_ctx->page_buf_size = fota_align_up(MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE, prog_size);

    ret = init_encryption();
    if (ret) {
        goto fail;
    }

    fota_ctx->effective_page_buf_size = fota_ctx->page_buf_size;

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_ctx->effective_page_buf_size -= FOTA_ENCRYPT_TAG_SIZE;
#elif (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
    // Reduce checksum size
    fota_ctx->effective_page_buf_size -= sizeof(fota_candidate_block_checksum_t);
#endif

    ret = fota_hash_start(&fota_ctx->curr_fw_hash_ctx);
    if (ret) {
        goto fail;
    }

    storage_start_addr = fota_candidate_get_config()->storage_start_addr;
    storage_end_addr = storage_start_addr + fota_candidate_get_config()->storage_size;
    ret = fota_bd_get_erase_size(storage_end_addr - 1, &erase_size);
    if (ret) {
        FOTA_TRACE_ERROR("Get erase size failed. ret %d", ret);
        goto fail;
    }

    // Check for storage size misconfiguration
    FOTA_ASSERT(storage_end_addr == fota_align_up(storage_end_addr, erase_size));
    storage_available = storage_end_addr - storage_start_addr;

    // Calculate needed space for FW data in storage:
    // This will align the non-encrypted image up to page buf size and recalculate the storage space
    // needed for interleaved data and tags in the encrypted case.
    storage_needed = fota_ctx->storage_addr - storage_start_addr +
                     fota_align_up(fota_ctx->fw_info->installed_size, fota_ctx->effective_page_buf_size) /
                     fota_ctx->effective_page_buf_size * fota_ctx->page_buf_size;

    if (storage_needed > storage_available) {
        FOTA_TRACE_ERROR("Insufficient storage for firmware");
        ret = FOTA_STATUS_INSUFFICIENT_STORAGE;
        goto fail;
    }

    fota_ctx->fw_header_offset = fota_ctx->storage_addr - fota_ctx->fw_header_bd_size;

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    ret = analyze_resume_state(&next_fota_state, storage_available);
    if (!ret && next_fota_state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        finalize_update();
        return;
    }
#else
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
#endif

    // Erase storage (if we're resuming, this has already been done)
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_INACTIVE) {
        uint32_t total_erase_size;

        // In case we support resume, erase all available storage, covering bad blocks on the way.
        // Otherwise, just erase needed storage.
#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
        total_erase_size = storage_available;
#else
        ret = fota_bd_get_erase_size(storage_start_addr + storage_needed - 1, &erase_size);
        if (ret) {
            FOTA_TRACE_ERROR("Get erase size failed %d", ret);
            goto fail;
        }
        total_erase_size = fota_align_up(storage_needed, erase_size);
#endif
        FOTA_TRACE_DEBUG("Erasing storage at 0x%lx, size %ld", storage_start_addr, total_erase_size);
        ret = fota_bd_erase(storage_start_addr, total_erase_size);
        if (ret) {
            FOTA_TRACE_ERROR("Erase storage failed %d", ret);
            ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
            goto fail;
        }

        // In non legacy headers we can and should program the FW header already here, as the candidate ready header
        // will be programmed at install phase, telling that the candidate is ready.
#if FOTA_HEADER_HAS_CANDIDATE_READY
        ret = prepare_and_program_header();
        if (ret) {
            goto fail;
        }
#endif
    }

    // At this point, we have converged to regular state, even if we were resuming
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;

    fota_ctx->page_buf = malloc(fota_ctx->page_buf_size);
    if (!fota_ctx->page_buf) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_ERROR("FOTA scratch buffer - allocation failed");
        goto fail;
    }

    fota_ctx->effective_page_buf = fota_ctx->page_buf + fota_ctx->page_buf_size - fota_ctx->effective_page_buf_size;

#if !defined(FOTA_DISABLE_DELTA)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        fota_ctx->delta_buf = malloc(MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE);
        if (!fota_ctx->delta_buf) {
            FOTA_TRACE_ERROR("FOTA delta buffer - allocation failed");
            ret = FOTA_STATUS_OUT_OF_MEMORY;
            goto fail;
        }

        ret = fota_delta_start(&fota_ctx->delta_ctx, comp_desc->curr_fw_read);
        if (ret) {
            goto fail;
        }
        FOTA_TRACE_DEBUG("FOTA delta engine initialized");
    }
#endif  // defined(FOTA_DISABLE_DELTA)

    fota_ctx->state = FOTA_STATE_DOWNLOADING;
    fota_source_report_state(FOTA_SOURCE_STATE_DOWNLOADING, NULL, NULL);

    ret = fota_source_firmware_request_fragment(fota_ctx->fw_info->uri, fota_ctx->payload_offset);
    if (ret) {
        goto fail;
    }

    return;

fail:
    FOTA_TRACE_DEBUG("Failed on download event. ret code %d", ret);
    abort_update(ret, "Failed on download authorization event");
}

static void fota_on_install_authorize(bool defer)
{
    int ret;
    const fota_component_desc_t *comp_desc;

    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;

#if FOTA_HEADER_HAS_CANDIDATE_READY
    ret = write_candidate_ready(comp_desc->name);
    if (ret) {
        FOTA_TRACE_ERROR("FOTA write_candidate_ready - failed %d", ret);
        goto fail;
    }
#else
    ret = prepare_and_program_header();
    if (ret) {
        FOTA_TRACE_ERROR("prepare_and_program_header - failed %d", ret);
        goto fail;
    }
#endif

    // Install defer means that we skip the installation for now
    if (defer) {
        if (fota_ctx->comp_id == MAIN_COMP_NUM) {
            // Main component is a special case - bootloader will install the FW upon next reset,
            // so no need to keep the manifest.
            fota_nvm_manifest_delete();
        } else {
            // All other components will use the resume flow for that, so manifest should be kept.
#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT != FOTA_RESUME_SUPPORT_RESUME
            abort_update(FOTA_STATUS_INSTALL_DEFER_UNSUPPORTED,
                         "Component install defer requires resume support");
            return;
#endif
        }
        update_cleanup();
        return;
    }

    fota_source_report_state(FOTA_SOURCE_STATE_UPDATING, install_component, on_state_set_failure);
    return;

fail:
    FOTA_TRACE_DEBUG("Failed on install authorization event. ret code %d", ret);
    abort_update(ret, "Failed on install authorization event");
}

void fota_on_authorize(uint32_t token, int32_t status)
{
    (void)status; //unused warning

    FOTA_ASSERT(fota_ctx);

    FOTA_ASSERT(fota_ctx->auth_token == token);
    FOTA_ASSERT(
        (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) ||
        (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION)
    )
    fota_ctx->auth_token = 0;

    if (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        FOTA_TRACE_INFO("Install authorization granted.");
        fota_on_install_authorize(false);
        return;
    }

    FOTA_TRACE_INFO("Download authorization granted.");
    fota_on_download_authorize();
}

static int program_to_storage(uint8_t *buf, uint32_t addr, uint32_t size)
{
    uint32_t data_size = size;
    uint32_t prog_size = size;
    uint8_t *src_buf = buf;
    uint8_t *prog_buf = buf;
    int ret;

    if (fota_ctx->effective_page_buf_size < fota_ctx->page_buf_size) {
        data_size = MIN(fota_ctx->effective_page_buf_size, size);
        prog_size = fota_ctx->page_buf_size;
        prog_buf = fota_ctx->page_buf;
    }

    // simple while-loop instead of check + do-while would take tens of bytes more from ROM
    if (!size) {
        goto exit;
    }

    do {

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        uint8_t *tag = fota_ctx->page_buf;
        ret = fota_encrypt_data(fota_ctx->enc_ctx, src_buf, data_size, src_buf, tag);
        if (ret) {
            FOTA_TRACE_ERROR("encryption failed %d", ret);
            return FOTA_STATUS_INTERNAL_ERROR;
        }
#elif MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
        fota_candidate_block_checksum_t *checksum = (fota_candidate_block_checksum_t *) fota_ctx->page_buf;
        *checksum = 0;
        for (uint32_t i = 0; i < data_size; i++) {
            *checksum += fota_ctx->effective_page_buf[i];
        }
#endif

        if (prog_size < fota_ctx->page_buf_size) {
            memset(fota_ctx->page_buf + prog_size, 0, fota_ctx->page_buf_size - prog_size);
            // We are on the very last page, align up to page buffer size
            prog_size = fota_align_up(prog_size, fota_ctx->page_buf_size);
        }
        ret = fota_bd_program(prog_buf, addr, prog_size);
        if (ret) {
            FOTA_TRACE_ERROR("Write to storage failed, address %" PRIu32 ", size %" PRIu32 " %d",
                             addr, size, ret);
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
        src_buf += data_size;
        addr += prog_size;
        size -= data_size;
        fota_ctx->fw_bytes_written += data_size;
        fota_ctx->storage_addr += prog_size;
    } while (size);

exit:
    return FOTA_STATUS_SUCCESS;
}

static int handle_fw_fragment(uint8_t *buf, size_t size, bool last)
{
    uint8_t *source_buf = buf, *prog_buf;
    uint32_t prog_size;
    uint32_t chunk;

    int ret = fota_hash_update(fota_ctx->curr_fw_hash_ctx, buf, size);
    if (ret) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    while (size) {
        // Two cases here:
        // 1. The "hard" one - If our fragment is not aligned to a whole page:
        //    In this case, just pull the remaining bytes into the page buf to complete the page.
        // 2. The "easy" one - fragment is aligned to a whole page:
        //    In this case, use source buffer directly and push as many pages as possible.
        if ((fota_ctx->effective_page_buf_size < fota_ctx->page_buf_size) ||
                fota_ctx->page_buf_offset || (size < fota_ctx->effective_page_buf_size)) {
            chunk = MIN(fota_ctx->effective_page_buf_size - fota_ctx->page_buf_offset, size);
            prog_size = fota_ctx->page_buf_offset + chunk;
            prog_buf = fota_ctx->effective_page_buf;
            memcpy(fota_ctx->effective_page_buf + fota_ctx->page_buf_offset, source_buf, chunk);
            fota_ctx->page_buf_offset = (fota_ctx->page_buf_offset + chunk) % fota_ctx->effective_page_buf_size;
        } else {
            chunk = fota_align_down(size, fota_ctx->effective_page_buf_size);
            prog_size = chunk;
            prog_buf = source_buf;
        }
        source_buf += chunk;

        if ((prog_size >= fota_ctx->effective_page_buf_size) || last) {
            ret = program_to_storage(prog_buf,
                                     fota_ctx->storage_addr,
                                     prog_size);
            if (ret) {
                FOTA_TRACE_ERROR("Failed writing to storage %d", ret);
                return FOTA_STATUS_STORAGE_WRITE_FAILED;
            }
        }
        size -= chunk;
    }
    return FOTA_STATUS_SUCCESS;
}

static void on_approve_state_delivered(void)
{
    FOTA_TRACE_DEBUG("Install Authorization requested");
    int ret = fota_app_on_install_authorization(fota_ctx->auth_token);
    if (ret) {
        abort_update(ret, "Failed to deliver install authorization");
    }
}

static int finalize_update(void)
{
    int ret;
    uint8_t curr_fw_hash_buf[FOTA_CRYPTO_HASH_SIZE];

    // Ongoing resume state here means that all authentication has been done before.
    // Can jump straight to finish.
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_ONGOING) {
        goto finished;
    }

    ret = fota_hash_result(fota_ctx->curr_fw_hash_ctx, curr_fw_hash_buf);
    if (ret) {
        return ret;
    }
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    ret = fota_verify_signature_prehashed(
              curr_fw_hash_buf,
              fota_ctx->fw_info->installed_signature, FOTA_IMAGE_RAW_SIGNATURE_SIZE
          );
    FOTA_FI_SAFE_COND(
        (ret == FOTA_STATUS_SUCCESS),
        FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
        "Candidate image is not authentic"
    );
#else
    FOTA_FI_SAFE_MEMCMP(curr_fw_hash_buf, fota_ctx->fw_info->installed_digest, FOTA_CRYPTO_HASH_SIZE,
                        FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
                        "Downloaded FW hash does not match manifest hash");
#endif

finished:
#if !defined(FOTA_DISABLE_DELTA)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        ret = fota_delta_finalize(&fota_ctx->delta_ctx);
        if (ret) {
            return ret;
        }
        fota_ctx->delta_ctx = 0;
    }
#endif

    FOTA_TRACE_INFO("Firmware download finished");

    ret = fota_gen_random((uint8_t *) &fota_ctx->auth_token, sizeof(fota_ctx->auth_token));
    if (ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }
    fota_ctx->state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;

    fota_source_report_state(FOTA_SOURCE_STATE_AWAITING_APPLICATION_APPROVAL, on_approve_state_delivered, on_state_set_failure);

    return FOTA_STATUS_SUCCESS;

fail:
    abort_update(ret, "Failed on fragment event");
    return ret;

}

void fota_on_fragment_failure(uint32_t token, int32_t status)
{
    FOTA_TRACE_ERROR("Failed to fetch fragment - %" PRId32, status);
    abort_update(FOTA_STATUS_DOWNLOAD_FRAGMENT_FAILED, "Failed to fetch fragment");
}

void fota_on_fragment(uint8_t *buf, size_t size)
{
    int ret = 0;
    bool last_fragment;

    FOTA_ASSERT(fota_ctx);

    uint32_t payload_bytes_left = fota_ctx->fw_info->payload_size - fota_ctx->payload_offset;

    if (size > payload_bytes_left) {
        abort_update(FOTA_STATUS_FW_SIZE_MISMATCH, "Got more bytes than expected");
        return;
    }

    fota_app_on_download_progress(fota_ctx->payload_offset, size, fota_ctx->fw_info->payload_size);

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
#if !defined(FOTA_DISABLE_DELTA)
        bool finished = false;
        // This loop will have a single iteration in all cases except for the last payload fragment,
        // in which it'll have an additional iteration, where it will draw all firmware fragments
        // that come after the last delta payload fragment.
        do {
            uint32_t actual_frag_size;
            if (payload_bytes_left) {
                ret = fota_delta_new_payload_frag(fota_ctx->delta_ctx, buf, size);
                if (ret == FOTA_STATUS_FW_DELTA_REQUIRED_MORE_DATA) {
                    payload_bytes_left -= size;
                    break;
                }
            } else {
                ret = fota_delta_payload_finished(fota_ctx->delta_ctx);
                size = 0;
                finished = true;
            }
            if (ret) {
                goto fail;
            }
            do {
                ret = fota_delta_get_next_fw_frag(fota_ctx->delta_ctx,
                                                  fota_ctx->delta_buf,
                                                  MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE,
                                                  &actual_frag_size);
                if (ret) {
                    goto fail;
                }
                if (actual_frag_size) {
                    last_fragment = ((fota_ctx->fw_bytes_written + fota_ctx->page_buf_offset + actual_frag_size) == fota_ctx->fw_info->installed_size);
                    ret = handle_fw_fragment(fota_ctx->delta_buf, actual_frag_size, last_fragment);
                    if (ret) {
                        goto fail;
                    }
                }
            } while (actual_frag_size);
            payload_bytes_left -= size;
        } while (!payload_bytes_left && !finished);
#else
        // we should not get here. The error is reported from fota_on_manifest
        FOTA_ASSERT(0);
#endif  // #if !defined(FOTA_DISABLE_DELTA)
    } else {
        last_fragment = ((payload_bytes_left - size) == 0);
        ret = handle_fw_fragment(buf, size, last_fragment);
        if (ret) {
            goto fail;
        }
        payload_bytes_left -= size;
    }

    fota_ctx->payload_offset += size;

    memset(buf, 0, size);

    if (!payload_bytes_left) {
        ret = finalize_update();
        if (ret) {
            goto fail;
        }
        return;
    }

    ret = fota_source_firmware_request_fragment(fota_ctx->fw_info->uri, fota_ctx->payload_offset);
    if (ret) {
        goto fail;
    }
    return;

fail:
    memset(buf, 0, size);
    abort_update(ret, "Failed on fragment event");
}


void fota_on_resume(uint32_t token, int32_t status)
{
    (void)token;  // unused
    (void)status;  // unused
    if (fota_ctx) {
        return;  // FOTA is already running - ignore
    }

    size_t manifest_size;
    uint8_t *manifest = malloc(FOTA_MANIFEST_MAX_SIZE);

    if (!manifest) {
        FOTA_TRACE_ERROR("FOTA manifest - allocation failed");
        abort_update(FOTA_STATUS_OUT_OF_MEMORY, "fota_on_resume");
        return;
    }

    memset(manifest, 0, FOTA_MANIFEST_MAX_SIZE);

    int ret = fota_nvm_manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (!ret) {
        FOTA_TRACE_INFO("Found manifest - resuming update");
        handle_manifest(manifest, manifest_size, /*is_resume*/ true);
    }

    free(manifest);

    if (ret == FOTA_STATUS_NOT_FOUND) {
        // silently ignore - no update to resume
        return;
    }
    if (ret) {
        FOTA_TRACE_ERROR("failed to load manifest from NVM (ret code %d) - update resume aborted.", ret);
    }
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
