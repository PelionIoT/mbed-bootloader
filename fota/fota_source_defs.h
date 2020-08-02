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

#ifndef __FOTA_SOURCE_DEFS_H_
#define __FOTA_SOURCE_DEFS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define FOTA_SOURCE_PACKAGE_OBJECT_ID           10252
#define FOTA_SOURCE_PACKAGE_RESOURCE_ID         1
#define FOTA_SOURCE_STATE_RESOURCE_ID           2
#define FOTA_SOURCE_UPDATE_RESULT_RESOURCE_ID   3
#define FOTA_SOURCE_PKG_NAME_RESOURCE_ID        5
#define FOTA_SOURCE_PKG_VERSION_RESOURCE_ID     6

#define FOTA_SOURCE_UPDATE_OBJECT_ID            10255
#define FOTA_SOURCE_PROTOCOL_SUPP_RESOURCE_ID   0
#define FOTA_SOURCE_VENDOR_RESOURCE_ID          3
#define FOTA_SOURCE_CLASS_RESOURCE_ID           4
#define FOTA_SOURCE_DEVICE_RESOURCE_ID          5

#define FOTA_SOURCE_SW_COMPONENT_OBJECT_ID      14
#define FOTA_SOURCE_COMP_NAME_RESOURCE_ID       0
#define FOTA_SOURCE_COMP_VERSION_RESOURCE_ID    2

#ifdef __cplusplus
}
#endif

#endif // __FOTA_SOURCE_DEFS_H_
