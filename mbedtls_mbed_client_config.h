//----------------------------------------------------------------------------
// The confidential and proprietary information contained in this file may
// only be used by a person authorised under and to the extent permitted
// by a subsisting licensing agreement from ARM Limited or its affiliates.
//
// (C) COPYRIGHT 2016 ARM Limited or its affiliates.
// ALL RIGHTS RESERVED
//
// This entire notice must be reproduced on all copies of this file
// and copies of this file may only be made by a person if such person is
// permitted to do so under the terms of a subsisting license agreement
// from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/* System support */
#define MBEDTLS_HAVE_ASM

/* Crypto flags */
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CMAC_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_X509_CREATE_C
//#define MBEDTLS_PLATFORM_TIME_ALT

/* mbed TLS feature support */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY
#define MBEDTLS_SSL_EXPORT_KEYS

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SSL_COOKIE_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C

// XXX mbedclient needs these: mbedtls_x509_crt_free, mbedtls_x509_crt_init, mbedtls_x509_crt_parse
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
// a bit wrong way to get mbedtls_ssl_conf_psk:

#undef MBEDTLS_SHA512_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_GCM_C

#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_X509_CRT_PARSE_C

// Remove RSA, save 20KB at total
#undef MBEDTLS_RSA_C
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

// Remove error messages, save 10KB of ROM
#undef MBEDTLS_ERROR_C

// Remove selftesting and save 11KB of ROM
#undef MBEDTLS_SELF_TEST

// Reduces ROM size by 30 kB
#undef MBEDTLS_ERROR_STRERROR_DUMMY
#undef MBEDTLS_VERSION_FEATURES
#undef MBEDTLS_DEBUG_C

// needed for parsing the certificates
#define MBEDTLS_PEM_PARSE_C
// dep of the previous
#define MBEDTLS_BASE64_C

// Needed by provisioning
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_CTR_DRBG_MAX_REQUEST 2048

// Reduce IO buffer to save RAM, default is 16KB
#define MBEDTLS_SSL_MAX_CONTENT_LEN 8096

// define to save 8KB RAM at the expense of ROM
#define MBEDTLS_AES_ROM_TABLES

// Save ROM and a few bytes of RAM by specifying our own ciphersuite list
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CUSTOM_CONFIG_H */
