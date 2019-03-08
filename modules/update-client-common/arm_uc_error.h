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

#ifndef ARM_UPDATE_ERROR_H
#define ARM_UPDATE_ERROR_H

#include <stdint.h>

// Use two characters to form the 16bit module code
#define TWO_CC(A,B) (((A) & 0xFF) | (((B) & 0xFF) << 8))
#define CC_ASCII(X) ((((X) < ' ') || ((X) > '~' )) ? '.' : (X))

#define MANIFEST_MANAGER_PREFIX    TWO_CC('M','M')
#define CERTIFICATE_MANAGER_PREFIX TWO_CC('C','M')
#define SOURCE_MANAGER_PREFIX      TWO_CC('S','M')
#define SOURCE_PREFIX              TWO_CC('S','E')
#define FIRMWARE_MANAGER_PREFIX    TWO_CC('F','M')
#define DER_PARSER_PREFIX          TWO_CC('D','P')
#define MBED_TLS_ERROR_PREFIX      TWO_CC('M','T')
#define UPDATE_CRYPTO_PREFIX       TWO_CC('C','U')
#define DEVICE_IDENTITY_PREFIX     TWO_CC('D','I')
#define HUB_PREFIX                 TWO_CC('H','B')
#define EVENT_QUEUE_PREFIX         TWO_CC('E','Q')
#define PAAL_PREFIX                TWO_CC('P','L')

#define ARM_UC_COMMON_ERR_LIST\
    ENUM_FIXED(ERR_NONE,0)\
    ENUM_AUTO(ERR_UNSPECIFIED)\
    ENUM_AUTO(ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ERR_NULL_PTR)\
    ENUM_AUTO(ERR_NOT_READY)\
    ENUM_AUTO(ERR_INVALID_STATE)\

// Manifest manager
#define ARM_UC_MM_ERR_LIST\
    ENUM_FIXED(MFST_ERR_FIRST, MANIFEST_MANAGER_PREFIX << 16)\
    ENUM_AUTO(MFST_ERR_NULL_PTR)\
    ENUM_AUTO(MFST_ERR_NOT_READY)\
    ENUM_AUTO(MFST_ERR_PENDING)\
    ENUM_AUTO(MFST_ERR_SIZE)\
    ENUM_AUTO(MFST_ERR_DER_FORMAT)\
    ENUM_AUTO(MFST_ERR_FORMAT)\
    ENUM_AUTO(MFST_ERR_VERSION)\
    ENUM_AUTO(MFST_ERR_ROLLBACK)\
    ENUM_AUTO(MFST_ERR_CRYPTO_MODE)\
    ENUM_AUTO(MFST_ERR_HASH)\
    ENUM_AUTO(MFST_ERR_GUID_VENDOR)\
    ENUM_AUTO(MFST_ERR_GUID_DEVCLASS)\
    ENUM_AUTO(MFST_ERR_GUID_DEVICE)\
    ENUM_AUTO(MFST_ERR_CFG_CREATE_FAILED)\
    ENUM_AUTO(MFST_ERR_KEY_SIZE)\
    ENUM_AUTO(MFST_ERR_CERT_INVALID)\
    ENUM_AUTO(MFST_ERR_CERT_NOT_FOUND)\
    ENUM_AUTO(MFST_ERR_CERT_READ)\
    ENUM_AUTO(MFST_ERR_INVALID_SIGNATURE)\
    ENUM_AUTO(MFST_ERR_INVALID_STATE)\
    ENUM_AUTO(MFST_ERR_BAD_EVENT)\
    ENUM_AUTO(MFST_ERR_EMPTY_FIELD)\
    ENUM_AUTO(MFST_ERR_NO_MANIFEST)\
    ENUM_AUTO(MFST_ERR_SIGNATURE_ALGORITHM)\
    ENUM_AUTO(MFST_ERR_UNSUPPORTED_CONDITION)\
    ENUM_AUTO(MFST_ERR_CTR_IV_SIZE)\
    ENUM_AUTO(MFST_ERR_MISSING_KEYTABLE)\
    ENUM_AUTO(MFST_ERR_BAD_KEYTABLE)\
    ENUM_AUTO(MFST_ERR_LAST)\

// Certificate Manager
#define ARM_UC_CM_ERR_LIST\
    ENUM_FIXED(ARM_UC_CM_ERR_FIRST, CERTIFICATE_MANAGER_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_CM_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ARM_UC_CM_ERR_NOT_FOUND)\
    ENUM_AUTO(ARM_UC_CM_ERR_INVALID_CERT)\
    ENUM_AUTO(ARM_UC_CM_ERR_BLACKLISTED)\
    ENUM_AUTO(ARM_UC_CM_ERR_LAST)\

// temporary declaration to avoid CI issues.
#define ARM_UC_CM_ERR_NONE ERR_NONE

// DER Parser
#define ARM_UC_DP_ERR_LIST\
    ENUM_FIXED(ARM_UC_DP_ERR_FIRST, DER_PARSER_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_DP_ERR_UNKNOWN)\
    ENUM_AUTO(ARM_UC_DP_ERR_NOT_FOUND)\
    ENUM_AUTO(ARM_UC_DP_ERR_NO_MORE_ELEMENTS)\
    ENUM_AUTO(ARM_UC_DP_ERR_LAST)\

// Source Manager
#define ARM_UC_SM_ERR_LIST\
    ENUM_FIXED(SOMA_ERR_FIRST, SOURCE_MANAGER_PREFIX << 16)\
    ENUM_AUTO(SOMA_ERR_UNSPECIFIED)\
    ENUM_AUTO(SOMA_ERR_NETWORK_TIMEOUT)\
    ENUM_AUTO(SOMA_ERR_CONNECTION_FAILURE)\
    ENUM_AUTO(SOMA_ERR_DNS_LOOKUP_FAILURE)\
    ENUM_AUTO(SOMA_ERR_CONNECTION_LOSS)\
    ENUM_AUTO(SOMA_ERR_NO_ROUTE_TO_SOURCE)\
    ENUM_AUTO(SOMA_ERR_SOURCE_REGISTRY_FULL)\
    ENUM_AUTO(SOMA_ERR_SOURCE_NOT_FOUND)\
    ENUM_AUTO(SOMA_ERR_INVALID_URI)\
    ENUM_AUTO(SOMA_ERR_INVALID_REQUEST)\
    ENUM_AUTO(SOMA_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(SOMA_ERR_INVALID_MANIFEST_STATE)\
    ENUM_AUTO(SOMA_ERR_INVALID_FW_STATE)\
    ENUM_AUTO(SOMA_ERR_INVALID_EVENT)\
    ENUM_AUTO(SOMA_ERR_LAST)\

// Source
#define ARM_UC_SRC_ERR_LIST\
    ENUM_FIXED(SRCE_ERR_FIRST, SOURCE_PREFIX << 16)\
    ENUM_AUTO(SRCE_ERR_UNINITIALIZED)\
    ENUM_AUTO(SRCE_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(SRCE_ERR_FAILED)\
    ENUM_AUTO(SRCE_ERR_ABORT)\
    ENUM_AUTO(SRCE_ERR_BUSY)\
    ENUM_AUTO(SRCE_ERR_LAST)\

// Firmware Manager
#define ARM_UC_FM_ERR_LIST\
    ENUM_FIXED(FIRM_ERR_FIRST, FIRMWARE_MANAGER_PREFIX << 16)\
    ENUM_AUTO(FIRM_ERR_WRITE)\
    ENUM_AUTO(FIRM_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(FIRM_ERR_INVALID_STATE)\
    ENUM_AUTO(FIRM_ERR_ACTIVATE)\
    ENUM_AUTO(FIRM_ERR_UNINITIALIZED)\
    ENUM_AUTO(FIRM_ERR_INVALID_HASH)\
    ENUM_AUTO(FIRM_ERR_FIRMWARE_TOO_LARGE)\
    ENUM_AUTO(FIRM_ERR_LAST)\

#define ARM_UC_CU_ERR_LIST\
    ENUM_FIXED(ARM_UC_CU_ERR_FIRST, UPDATE_CRYPTO_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_CU_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ARM_UC_CU_ERR_LAST)\

#define ARM_UC_DI_ERR_LIST\
    ENUM_FIXED(ARM_UC_DI_ERR_FIRST, DEVICE_IDENTITY_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_DI_ERR_INVALID_PARAMETER)\
    ENUM_AUTO(ARM_UC_DI_ERR_NOT_READY)\
    ENUM_AUTO(ARM_UC_DI_ERR_NOT_FOUND)\
    ENUM_AUTO(ARM_UC_DI_ERR_SIZE)\
    ENUM_AUTO(ARM_UC_DI_ERR_LAST)\

#define ARM_UC_HB_ERR_LIST\
    ENUM_FIXED(HUB_ERR_FIRST, HUB_PREFIX << 16)\
    ENUM_AUTO(HUB_ERR_INTERNAL_ERROR)\
    ENUM_AUTO(HUB_ERR_ROLLBACK_PROTECTION)\
    ENUM_AUTO(ARM_UC_HUB_ERR_NOT_AVAILABLE)\
    ENUM_AUTO(HUB_ERR_CONNECTION)\
    ENUM_AUTO(HUB_ERR_LAST)\

#define ARM_UC_EQ_ERR_LIST\
    ENUM_FIXED(ARM_UC_EQ_ERR_FIRST, EVENT_QUEUE_PREFIX << 16)\
    ENUM_AUTO(ARM_UC_EQ_ERR_POOL_EXHAUSTED)\
    ENUM_AUTO(ARM_UC_EQ_ERR_FAILED_TAKE)\
    ENUM_AUTO(ARM_UC_EQ_ERR_LAST)\

// PAAL
#define ARM_UC_PAAL_ERR_LIST\
    ENUM_FIXED(PAAL_ERR_FIRST, PAAL_PREFIX << 16)\
    ENUM_AUTO(PAAL_ERR_FIRMWARE_TOO_LARGE)\
    ENUM_AUTO(PAAL_ERR_LAST)\

#define ARM_UC_ERR_LIST\
    ARM_UC_COMMON_ERR_LIST\
    ARM_UC_MM_ERR_LIST\
    ARM_UC_CM_ERR_LIST\
    ARM_UC_DP_ERR_LIST\
    ARM_UC_SM_ERR_LIST\
    ARM_UC_SRC_ERR_LIST\
    ARM_UC_FM_ERR_LIST\
    ARM_UC_CU_ERR_LIST\
    ARM_UC_DI_ERR_LIST\
    ARM_UC_HB_ERR_LIST\
    ARM_UC_EQ_ERR_LIST\
    ARM_UC_PAAL_ERR_LIST\

enum arm_uc_error {
#define ENUM_AUTO(name) name,
#define ENUM_FIXED(name, val) name = val,
    ARM_UC_ERR_LIST
#undef ENUM_AUTO
#undef ENUM_FIXED
};
union arm_uc_error_code {
    int32_t code;
    struct {
        int16_t error;
        union {
            uint16_t module;
            uint8_t  modulecc[2];
        };
    };
};

typedef union arm_uc_error_code arm_uc_error_t;

#define ARM_UC_ERROR(CODE)              ((arm_uc_error_t){ CODE })
#define ARM_UC_IS_ERROR(VAR)            ((VAR).code != ERR_NONE)
#define ARM_UC_IS_NOT_ERROR(VAR)        (!ARM_UC_IS_ERROR(VAR))
#define ARM_UC_ERROR_MATCHES(VAR,CODE)  ((VAR).code == CODE)

#define ARM_UC_CLEAR_ERROR(ERR)         ((ERR).code = (ERR_NONE))
#define ARM_UC_INIT_ERROR(VAR, CODE)    arm_uc_error_t (VAR) = arm_uc_code_to_error( CODE )
#define ARM_UC_GET_ERROR(VAR)           ((VAR).code)

#if ARM_UC_ERROR_TRACE_ENABLE
#define ARM_UC_SET_ERROR(VAR, CODE)\
    do { (VAR).code = (CODE);\
    if ( ARM_UC_IS_ERROR(VAR) ) \
        UC_ERROR_TRACE("set error %" PRIx32, (long unsigned int)CODE);\
    } while (0)
#else
#define ARM_UC_SET_ERROR(VAR, CODE)                 (VAR).code = (CODE)
#endif
// have a way to set errors without trace for values that are not strictly errors.
#define ARM_UC_SET_ERROR_NEVER_TRACE(VAR, CODE)     (VAR).code = (CODE)

#ifdef __cplusplus
extern "C" {
#endif

const char *ARM_UC_err2Str(arm_uc_error_t err);
static inline arm_uc_error_t arm_uc_code_to_error(int32_t code)
{
    arm_uc_error_t err;
    err.code = code;
    return err;
}

#ifdef __cplusplus
}
#endif
#endif // ARM_UPDATE_ERROR_H
