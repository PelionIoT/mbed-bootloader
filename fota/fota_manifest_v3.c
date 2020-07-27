
// ----------------------------------------------------------------------------
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

#if (FOTA_MANIFEST_SCHEMA_VERSION == 3)

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#include "fota/fota_manifest.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"
#include "fota/fota_crypto.h"
#include "fota/fota_crypto_asn_extra.h"
#include "fota/fota_base.h"
#include "fota/fota_nvm.h"
#include "fota/fota_crypto.h"
#include "mbedtls/asn1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

/*
 * DeltaMetadata ::= SEQUENCE {
 *   installed-size INTEGER,
 *   installed-digest OCTET STRING,
 *   precursor-digest OCTET STRING
 * }
 */

int parse_delta_metadata(
    const uint8_t *metadata, size_t metadata_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data
)
{
    unsigned char *p = (unsigned char *) metadata;
    const unsigned char *metadata_end = metadata + metadata_size;
    size_t len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse DeltaMetadata:installed-size @%d",  p - input_data);
    int tls_status = mbedtls_asn1_get_int(&p, metadata_end, (int *) &fw_info->installed_size);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading DeltaMetadata:installed-size %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("DeltaMetadata:installed-size %" PRIu32, fw_info->installed_size);

    FOTA_MANIFEST_TRACE_DEBUG("Parse DeltaMetadata:installed-digest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, metadata_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading DeltaMetadata:installed-digest %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (FOTA_CRYPTO_HASH_SIZE != len) {
        FOTA_TRACE_ERROR("DeltaMetadata:installed-digest too long %zu", len);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    memcpy(fw_info->installed_digest, p, len);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse DeltaMetadata:precursor-digest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, metadata_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading DeltaMetadata:precursor-digest %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (FOTA_CRYPTO_HASH_SIZE != len) {
        FOTA_TRACE_ERROR("DeltaMetadata:precursor-digest too long %zu", len);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    memcpy(fw_info->precursor_digest, p, len);

    return FOTA_STATUS_SUCCESS;

}


/*
 * Manifest ::= SEQUENCE {
 *   vendor-id OCTET STRING,
 *   class-id OCTET STRING,
 *   update-priority INTEGER,
 *   component-name UTF8String,
 *   payload-version UTF8String,
 *   payload-digest OCTET STRING,
 *   payload-size INTEGER,
 *   payload-uri UTF8String,
 *   payload-format ENUMERATED {
 *     raw-binary(1),
 *     arm-patch-stream(5)
 *   },
 *   installed-signature OCTET STRING,
 *   delta-metadata DeltaMetadata OPTIONAL,
 *   vendor-data OCTET STRING OPTIONAL
 * }
 */
int parse_manifest_internal(
    const uint8_t *manifest, size_t manifest_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data)
{
    int fota_status = FOTA_STATUS_INTERNAL_ERROR;
    const unsigned char *manifest_end = manifest + manifest_size;
    unsigned char *p = (unsigned char *) manifest;
    bool is_delta = false;
    size_t len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:vendor-id @%d",  p - input_data);
    int tls_status = mbedtls_asn1_get_tag(
                         &p, manifest_end, &len,
                         MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:vendor-id %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    uint8_t fota_id[FOTA_GUID_SIZE] = {0};
    fota_status = fota_nvm_get_vendor_id(fota_id);
    if (fota_status != FOTA_STATUS_SUCCESS) {
        FOTA_TRACE_ERROR("failed to get vendor_id error=%d", fota_status);
        return fota_status;
    }
    if (len != sizeof(fota_id) || (memcmp(fota_id, p, len))) {
        FOTA_TRACE_ERROR("vendor_id mismatch");
        return FOTA_STATUS_MANIFEST_WRONG_VENDOR_ID;
    }
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)

    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:class-id @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:class-id %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    memset(fota_id, 0, FOTA_GUID_SIZE);
    fota_status = fota_nvm_get_class_id(fota_id);
    if (fota_status != FOTA_STATUS_SUCCESS) {
        FOTA_TRACE_ERROR("failed to get class_id error=%d", fota_status);
        return fota_status;
    }
    if (len != sizeof(fota_id) || (memcmp(fota_id, p, len))) {
        FOTA_TRACE_ERROR("class_id mismatch");
        return FOTA_STATUS_MANIFEST_WRONG_CLASS_ID;
    }
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:update-priority @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int(&p, manifest_end, (int *) &fw_info->priority);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:update-priority %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Manifest:update-priority %" PRIu32, fw_info->priority);

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:component-name @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:component-name %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len >= FOTA_COMPONENT_MAX_NAME_SIZE) {
        FOTA_TRACE_ERROR("component-name too long %zu", len);
        return FOTA_STATUS_MANIFEST_SEMVER_ERROR;
    }
    memcpy(fw_info->component_name, p, len);
    FOTA_MANIFEST_TRACE_DEBUG("component-name %s", fw_info->component_name);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-version @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-version %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    if (len >= FOTA_COMPONENT_MAX_SEMVER_STR_SIZE) {
        FOTA_TRACE_ERROR("Manifest:payload-version too long %zu", len);
        return FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED;
    }
    char sem_ver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = { 0 };
    memcpy(sem_ver, p, len);
    fota_status = fota_component_version_semver_to_int(sem_ver, &fw_info->version);
    if (fota_status != FOTA_STATUS_SUCCESS) {
        return fota_status;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-version %d", sem_ver);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-digest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-digest %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len > FOTA_CRYPTO_HASH_SIZE) {
        FOTA_TRACE_ERROR("Manifest:payload-digest size is too big %zu", len);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    memcpy(fw_info->payload_digest, p, len);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-size @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int(&p, manifest_end, (int *) &fw_info->payload_size);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-size %d", tls_status);
        return FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-size %" PRIu32, fw_info->payload_size);

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-url @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-url %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len >= FOTA_MANIFEST_URI_SIZE) {
        FOTA_TRACE_ERROR("Manifest:payload-url too long %zu", len);
        return FOTA_STATUS_MANIFEST_INVALID_URI;
    }
    memcpy(fw_info->uri, p, len);
    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-url %s", fw_info->uri);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-format @%d",  p - input_data);
    int payload_format_value = 0;
    tls_status = mbedtls_asn1_get_enumerated_value(&p, manifest_end, &payload_format_value);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-format %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-format %d", payload_format_value);
    fw_info->payload_format = payload_format_value;
    if (payload_format_value == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        is_delta = true;
    } else if (payload_format_value != FOTA_MANIFEST_PAYLOAD_FORMAT_RAW) {
        FOTA_TRACE_ERROR("error unsupported payload format %d - ", payload_format_value);
        return FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:installed-signature @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status == 0) {
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
        if (FOTA_IMAGE_RAW_SIGNATURE_SIZE != len) {
            FOTA_TRACE_ERROR("installed-signature len is invalid %d (expected %d)", len, FOTA_IMAGE_RAW_SIGNATURE_SIZE);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }
        memcpy(fw_info->installed_signature, p, len);
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
        p += len;
    } else {
        FOTA_MANIFEST_TRACE_DEBUG("installed-signature not found ptr=%p", p);
    }

    if (is_delta) {
        FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:delta-metadata @%d",  p - input_data);
        tls_status = mbedtls_asn1_get_tag(
                         &p, manifest_end, &len,
                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (tls_status != 0) {
            FOTA_TRACE_ERROR("Error reading Manifest:delta-metadata %d", tls_status);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }


        fota_status = parse_delta_metadata(p, len, fw_info, input_data);
        if (fota_status != 0) {
            FOTA_TRACE_ERROR("Error parse_delta_metadata %d", fota_status);
            return fota_status;
        }

        p += len;

    } else {
        /*for the ease of use we will fill in payload size and digest values */
        memcpy(fw_info->installed_digest, fw_info->payload_digest, FOTA_CRYPTO_HASH_SIZE);
        fw_info->installed_size = fw_info->payload_size;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:vendor-data @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status == 0) {
        if (FOTA_MANIFEST_VENDOR_DATA_SIZE < len) {
            FOTA_TRACE_ERROR("Manifest:vendor-data too long %zu", len);
            return FOTA_STATUS_MANIFEST_WRONG_VENDOR_ID;
        }
        memcpy(fw_info->vendor_data, p, len);

        p += len;
    } else {
        FOTA_MANIFEST_TRACE_DEBUG("vendor-data not found");
    }

    FOTA_DBG_ASSERT(p == manifest_end);

    return FOTA_STATUS_SUCCESS;
}

/*
 * Assuming following ASN1 schema
 * SignedResource ::= SEQUENCE {
 *  manifest-version ENUMERATED {
 *    v3(3)
 *  },
 *  manifest Manifest,
 *  signature OCTET STRING
 */
int fota_manifest_parse(
    const uint8_t *input_data, size_t input_size,
    manifest_firmware_info_t *fw_info
)
{
    FOTA_DBG_ASSERT(input_data);
    FOTA_DBG_ASSERT(input_size);
    FOTA_DBG_ASSERT(fw_info);

    memset(fw_info, 0, sizeof(*fw_info));

    int ret = FOTA_STATUS_MANIFEST_MALFORMED;  // used by FOTA_FI_SAFE_COND
    int fota_sig_status = FOTA_STATUS_MANIFEST_MALFORMED;  // must be set to error
    int tmp_status;  // reusable status
    size_t len = input_size;
    unsigned char *p = (unsigned char *)input_data;
    unsigned char *signed_resource_end = p + len;

    unsigned char *int_manifest = 0;
    size_t int_manifest_size = 0;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_tag(
                     &p, signed_resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error SignedResource tag %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (p + len > signed_resource_end) {
        FOTA_TRACE_ERROR("Error got truncated manifest");
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    // input data size may be bigger than real manifest due to storage limitations.
    // update real resource end
    signed_resource_end = p + len;

    int manifest_format_version = 0;
    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource:version @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_enumerated_value(&p, signed_resource_end, &manifest_format_version);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource:version %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("SignedResource:version %d", manifest_format_version);

    if (FOTA_MANIFEST_SCHEMA_VERSION != manifest_format_version) {
        FOTA_TRACE_ERROR("wrong manifest schema version version %d", manifest_format_version);
        return FOTA_STATUS_MANIFEST_SCHEMA_UNSUPPORTED;
    }

    uint8_t *signed_data_ptr = p;
    size_t signed_data_size;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource:manifest @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_tag(
                     &p, signed_resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource:manifest %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    signed_data_size = p + len - signed_data_ptr;

    int_manifest = p;
    int_manifest_size = len;
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource:signature @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_tag(
                     &p, signed_resource_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource:signature %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)

    fota_sig_status = fota_verify_signature(
                          signed_data_ptr, signed_data_size,
                          p, len);
    FOTA_FI_SAFE_COND(
        fota_sig_status == FOTA_STATUS_SUCCESS,
        fota_sig_status,
        "fota_verify_signature failed %d", fota_sig_status
    );
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)

    p += len;

    tmp_status = parse_manifest_internal(
                     int_manifest, int_manifest_size,
                     fw_info, input_data);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("parse_manifest_internal failed %d", tmp_status);
        return tmp_status;
    }

    FOTA_MANIFEST_TRACE_DEBUG("status = %d", FOTA_STATUS_SUCCESS);
    return FOTA_STATUS_SUCCESS;
fail:
    return ret;
}
#endif

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
