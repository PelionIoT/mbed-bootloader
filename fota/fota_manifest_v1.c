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

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "fota/fota_status.h"
#include "fota/fota_manifest.h"
#include "fota/fota_crypto.h"
#include "fota/fota_crypto_asn_extra.h"
#include "fota/fota_nvm.h"
#include "mbedtls/asn1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#if (FOTA_MANIFEST_SCHEMA_VERSION == 1)

#ifndef FOTA_MANIFEST_RESOURCE_TYPE
#define FOTA_MANIFEST_RESOURCE_TYPE         0
#endif

/*
 * PayloadDescription ::= SEQUENCE {
 *    format      CHOICE {
 *        enum    ENUMERATED {
 *            undefined(0), raw-binary(1), cbor(2), hex-location-length-data(3), elf(4), bsdiff-stream(5)
 *        },
 *        objectId    OBJECT IDENTIFIER
 *    },
 *    encryptionInfo SEQUENCE {
 *        initVector OCTET STRING,
 *        id CHOICE {
 *            key OCTET STRING,
 *            certificate CertificateReference
 *        },
 *        key      CHOICE {
 *           keyTable  Uri,
 *            cipherKey OCTET STRING
 *         } OPTIONAL
 *     } OPTIONAL,
 *     storageIdentifier UTF8String,
 *     reference    ResourceReference,
 *     installedSize INTEGER OPTIONAL,    <--------- starting from here
 *     installedDigest OCTET STRING OPTIONAL,
 *     version     UTF8String OPTIONAL
 * }
 *
 */
int parse_delta_metadata(
    const uint8_t *metadata, size_t metadata_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data
)
{
    unsigned char *p = (unsigned char *) metadata;
    const unsigned char *metadata_end = metadata + metadata_size;
    size_t len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadDescription:installedSize @%d",  p - input_data);
    int tls_status = mbedtls_asn1_get_int(&p, metadata_end, (int *) &fw_info->installed_size);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadDescription:installedSize %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("PayloadDescription:installedSize %" PRIu32, fw_info->installed_size);

    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadDescription:installedDigest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, metadata_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadDescription:installedDigest %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (FOTA_CRYPTO_HASH_SIZE != len) {
        FOTA_TRACE_ERROR("PayloadDescription:installedDigest too long %d", len);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    memcpy(fw_info->installed_digest, p, len);

    return FOTA_STATUS_SUCCESS;
}
/*
 * PayloadDescription ::= SEQUENCE {
 *    format      CHOICE {
 *        enum    ENUMERATED {
 *            undefined(0), raw-binary(1), cbor(2), hex-location-length-data(3), elf(4), bsdiff-stream(5)
 *        },
 *        objectId    OBJECT IDENTIFIER
 *    },
 *    encryptionInfo SEQUENCE {
 *        initVector OCTET STRING,
 *        id CHOICE {
 *            key OCTET STRING,
 *            certificate CertificateReference
 *        },
 *        key      CHOICE {
 *           keyTable  Uri,
 *            cipherKey OCTET STRING
 *         } OPTIONAL
 *     } OPTIONAL,
 *     storageIdentifier UTF8String,
 *     reference    ResourceReference,
 *     installedSize INTEGER OPTIONAL,
 *     installedDigest OCTET STRING OPTIONAL,
 *     version     UTF8String OPTIONAL
 * }
 *
 */
int parse_payload_description(
    const uint8_t *desc_data, size_t desc_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data)
{

    int fota_status = FOTA_STATUS_INTERNAL_ERROR;
    unsigned char *p = (unsigned char *) desc_data;
    const unsigned char *desc_end = desc_data + desc_size;
    size_t len;
    bool is_delta = false;

    //PayloadDescription:format
    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadDescription:format @%d",  p - input_data);
    int payload_format_value = 0;
    int tls_status = mbedtls_asn1_get_enumerated_value(&p, desc_end, &payload_format_value);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadDescription:format %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("PayloadDescription:format %d", payload_format_value);
    fw_info->payload_format = payload_format_value;
    if (payload_format_value == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        is_delta = true;
    } else if (payload_format_value != FOTA_MANIFEST_PAYLOAD_FORMAT_RAW) {
        FOTA_TRACE_ERROR("error unsupported payload format %d - ", payload_format_value);
        return FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
    }

    // assuming PayloadDescription:encryptionInfo is empty

    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadDescription:storageIdentifier @%d",  p - input_data);
    len = 0;
    tls_status = mbedtls_asn1_get_tag(
                     &p, desc_end, &len,
                     MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadDescription:storageIdentifier %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadDescription:reference @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, desc_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadDescription:reference %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Parse ResourceReference:hash @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, desc_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading ResourceReference:hash %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len > FOTA_CRYPTO_HASH_SIZE) {
        FOTA_TRACE_ERROR("ResourceReference:hash size is too big %zu", len);
        return FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED;
    }
    memcpy(fw_info->payload_digest, p, len);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse ResourceReference:uri @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, desc_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading ResourceReference:uri %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len >= FOTA_MANIFEST_URI_SIZE) {
        FOTA_TRACE_ERROR("ResourceReference:uri too long %zu", len);
        return FOTA_STATUS_MANIFEST_INVALID_URI;
    }
    memcpy(fw_info->uri, p, len);
    FOTA_MANIFEST_TRACE_DEBUG("payload-url %s", fw_info->uri);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse ResourceReference:size @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int(&p, desc_end, (int *) &fw_info->payload_size);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading ResourceReference:size %d", tls_status);
        return FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED;
    }
    FOTA_MANIFEST_TRACE_DEBUG("ResourceReference:size %" PRIu32, fw_info->payload_size);

    if (is_delta) {
        FOTA_MANIFEST_TRACE_DEBUG("DeltaMetadata offset %d",  p - desc_data);

        fota_status = parse_delta_metadata(p, desc_end - p, fw_info, input_data);
        if (fota_status != 0) {
            FOTA_TRACE_ERROR("Error reading delta metadata %d", fota_status);
            return fota_status;
        }


        p += len;

    } else {
        /*for the ease of use we will fill in payload size and digest values */
        memcpy(fw_info->installed_digest, fw_info->payload_digest, FOTA_CRYPTO_HASH_SIZE);
        fw_info->installed_size = fw_info->payload_size;
    }

    return FOTA_STATUS_SUCCESS;
}
/*
 * Manifest ::= SEQUENCE {
 *   manifestVersion     ENUMERATED,
 *   description UTF8String OPTIONAL,
 *   timestamp   INTEGER,
 *   vendor-id   OCTET STRING,
 *   class-id    OCTET STRING,
 *   deviceId    UUID,
 *   nonce       OCTET STRING,
 *   vendorInfo  OCTET STRING,
 *   applyPeriod OCTET STRING OPTIONAL,
 *   applyImmediately    BOOLEAN,
 *   priority     INTEGER OPTIONAL,
 *   encryptionMode  CHOICE,
 *   aliases         SEQUENCE OF ResourceAlias,
 *   dependencies    SEQUENCE OF ResourceReference,
 *   payload         PayloadDescription OPTIONAL
 * }
 */
int parse_manifest_internal(
    const uint8_t *manifest, size_t manifest_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data)
{
    int fota_status = FOTA_STATUS_INTERNAL_ERROR;
    int tls_status;

    const unsigned char *manifest_end = manifest + manifest_size;
    unsigned char *p = (unsigned char *) manifest;
    size_t len;
    int manifest_format_version = 0;

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:manifestVersion @%d", (p - input_data));
    tls_status = mbedtls_asn1_get_enumerated_value(&p, manifest_end, &manifest_format_version);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:manifestVersion %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Manifest:manifestVersion %d", manifest_format_version);

    if (FOTA_MANIFEST_SCHEMA_VERSION != manifest_format_version) {
        FOTA_TRACE_ERROR("wrong manifest schema version version %d", manifest_format_version);
        return FOTA_STATUS_MANIFEST_SCHEMA_UNSUPPORTED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:description OPTIONAL @%d", (p - input_data));
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        FOTA_MANIFEST_TRACE_DEBUG("Description OPTIONAL is missing");
    } else {
        p += len;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:timestamp (payload-version) @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int64(&p, manifest_end, (int64_t *) &fw_info->version);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading payload-version (timestamp) %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("version %" PRIu64, fw_info->version);

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:vendorId @ offset %d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:vendorId %d", tls_status);
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

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:classId @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:classId %d", tls_status);
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

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:deviceId @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:deviceId %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:nonce @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:nonce %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    p += len;
    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:vendorInfo @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);

    if (tls_status == 0) {
        if (FOTA_MANIFEST_VENDOR_DATA_SIZE < len) {
            FOTA_TRACE_ERROR("Manifest:vendorInfo too long %zu", len);
            return FOTA_STATUS_MANIFEST_WRONG_VENDOR_ID;
        }
        memcpy(fw_info->vendor_data, p, len);

        p += len;
    } else {
        FOTA_TRACE_ERROR("Error reading Manifest:vendorInfo %d", tls_status);
    }
    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:precursorDigest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        FOTA_MANIFEST_TRACE_DEBUG("Manifest:precursorDigest is missing");
    } else {
        if (FOTA_CRYPTO_HASH_SIZE != len) {
            FOTA_TRACE_ERROR("Manifest:precursorDigest too long %d", len);
            return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        }
        memcpy(fw_info->precursor_digest, p, len);
        p += len;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:applyImmediately @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_BOOLEAN);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading  Manifest:applyImmediately %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:priority OPTIONAL @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int(&p, manifest_end, (int *) &fw_info->priority);
    if (tls_status == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        FOTA_MANIFEST_TRACE_DEBUG("Manifest:priority OPTIONALs is missing");
        fw_info->priority = 0;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:encryptionMode @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(&p, manifest_end, &len, MBEDTLS_ASN1_ENUMERATED);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:encryptionMode %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:aliases @%d",  p - input_data);
    mbedtls_asn1_sequence cur;
    tls_status = mbedtls_asn1_get_sequence_of(
                     &p, manifest_end, &cur,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tls_status == MBEDTLS_ERR_ASN1_LENGTH_MISMATCH) {
        FOTA_MANIFEST_TRACE_DEBUG("Manifest:aliases - empty");
    } else {
        if (tls_status != 0) {
            FOTA_TRACE_ERROR("Error reading Manifest:aliases %d", tls_status);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }
    }

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:dependencies @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_sequence_of(
                     &p, manifest_end, &cur,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tls_status == MBEDTLS_ERR_ASN1_LENGTH_MISMATCH) {
        FOTA_MANIFEST_TRACE_DEBUG("Manifest:dependencies - empty");
    } else {
        if (tls_status != 0) {
            FOTA_TRACE_ERROR("Error reading Manifest:dependencies %d", tls_status);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }
    }

    FOTA_MANIFEST_TRACE_DEBUG("Reading Manifest:payload OPTIONAL @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tls_status == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload OPTIONAL is missing");
    } else if (tls_status == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
        FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload OPTIONAL - empty");
        p += 2;
    }

    fota_status = parse_payload_description(
                      p,
                      (manifest_end - p),
                      fw_info, input_data);
    if (fota_status != 0) {
        FOTA_TRACE_ERROR("Error parse_payload_description %d", fota_status);
        return fota_status;
    }

    return FOTA_STATUS_SUCCESS;
}


/*
 * Assuming following ASN1 schema
 * SignedResource ::= SEQUENCE {
 *    resource  Resource,
 *    signature ResourceSignature
 * }
 * ResourceSignature ::= SEQUENCE {
 *    hash        OCTET STRING,
 *    signatures SEQUENCE OF SignatureBlock,
 *    macs       SEQUENCE OF MacBlock OPTIONAL
 * }
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

    unsigned char *signed_data_ptr = 0;
    unsigned char *resource = 0;
    unsigned char *p = (unsigned char *)input_data;
    unsigned char *resource_end = p + len;

    mbedtls_asn1_sequence cur;
    mbedtls_asn1_sequence *cur_ptr = &(cur);

    size_t signed_data_size = 0;
    int resource_type = -1;

    FOTA_MANIFEST_TRACE_DEBUG("SignedResource @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &p, resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource tag %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    if (p + len > resource_end) {
        FOTA_TRACE_ERROR("Error got truncated manifest");
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    // input data size may be bigger than real manifest due to storage limitations.
    // update real resource end
    resource_end = p + len;
    signed_data_ptr = p;

    FOTA_MANIFEST_TRACE_DEBUG("Reading Resource @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &p, resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading Resource %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_DBG_ASSERT(resource_end >= p + len);

    signed_data_size = p + len - signed_data_ptr;
    FOTA_MANIFEST_TRACE_DEBUG("Resource size = %zu", signed_data_size);

    resource = p;  // saved for later use - will check signature first
    p += len;  // jump over resource element

    FOTA_MANIFEST_TRACE_DEBUG("Reading ResourceSignature @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &p, resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading ResourceSignature %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_DBG_ASSERT(resource_end >= p + len);

    FOTA_MANIFEST_TRACE_DEBUG("Reading ResourceSignature:hash @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &p, resource_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading hash %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    p += len;  // jump over hash element

    FOTA_MANIFEST_TRACE_DEBUG("Reading ResourceSignature:signatures @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_sequence_of(
                     &p, resource_end, cur_ptr,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading ResourceSignature:signatures %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Reading ResourceSignature:signatures[0] @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &(cur_ptr->buf.p), resource_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading ResourceSignature:signatures[0] %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_DBG_ASSERT(resource_end >= cur_ptr->buf.p + len);
#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    // Make sure fota_status has erroneous value before the call
    fota_sig_status = fota_verify_signature(
                          signed_data_ptr, signed_data_size,
                          cur_ptr->buf.p, len);
    FOTA_FI_SAFE_COND(
        fota_sig_status == FOTA_STATUS_SUCCESS,
        fota_sig_status,
        "fota_verify_signature failed %d", fota_sig_status
    );
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)

    if (cur_ptr->next != NULL) {
        FOTA_MANIFEST_TRACE_DEBUG("Could be only one sequence");
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    p = resource;
    FOTA_MANIFEST_TRACE_DEBUG("Reading Resource:uri OPTIONAL @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &p, resource_end, &len,
                     MBEDTLS_ASN1_UTF8_STRING);
    if (tmp_status == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        FOTA_MANIFEST_TRACE_DEBUG("Resource:uri OPTIONAL is missing");
    } else {
        p += len;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Reading Resource:resourceType @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_enumerated_value(&p, resource_end, &resource_type);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading Resource:resourceType %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Resource:resourceType=%d", resource_type);

    if (FOTA_MANIFEST_RESOURCE_TYPE != resource_type) {
        FOTA_TRACE_ERROR("wrong resource type %d, payload not supported", resource_type);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Resource:Manifest @%d", (p - input_data));
    tmp_status = mbedtls_asn1_get_tag(
                     &p, resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading Resource:Manifest %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    FOTA_DBG_ASSERT(resource_end >= p + len);

    tmp_status = parse_manifest_internal(
                     p, len,
                     fw_info,
                     input_data);
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
