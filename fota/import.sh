#!/bin/bash -e
# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion Ltd.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------


CLOUD_CLIENT=${1:?"missing fota directory path"}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

declare -a FOTA_FILES=(
        "$CLOUD_CLIENT/fota/fota_base.h"
        "$CLOUD_CLIENT/fota/fota_block_device.cpp"
        "$CLOUD_CLIENT/fota/fota_block_device.h"
        "$CLOUD_CLIENT/fota/fota_candidate.c"
        "$CLOUD_CLIENT/fota/fota_candidate.h"
        "$CLOUD_CLIENT/fota/fota_component.c"
        "$CLOUD_CLIENT/fota/fota_component_defs.h"
        "$CLOUD_CLIENT/fota/fota_component.h"
        "$CLOUD_CLIENT/fota/fota_component_internal.h"
        "$CLOUD_CLIENT/fota/fota_config.h"
        "$CLOUD_CLIENT/fota/fota_crypto.c"
        "$CLOUD_CLIENT/fota/fota_crypto_defs.h"
        "$CLOUD_CLIENT/fota/fota_crypto.h"
        "$CLOUD_CLIENT/fota/fota_header_info.h"
        "$CLOUD_CLIENT/fota/fota_header_info_v3.c"
        "$CLOUD_CLIENT/fota/fota_internal.h"
        "$CLOUD_CLIENT/fota/fota_nvm.h"
        "$CLOUD_CLIENT/fota/fota_nvm_int.h"
        "$CLOUD_CLIENT/fota/fota_platform.h"
        "$CLOUD_CLIENT/fota/fota_platform_default.c"
        "$CLOUD_CLIENT/fota/fota_status.h"
        "$CLOUD_CLIENT/fota/mbed_lib.json"
)

for file in "${FOTA_FILES[@]}"
do
   cp -v $file $SCRIPT_DIR
done

echo "Imported from mbed-cloud-client-internal at hash: $(git -C $CLOUD_CLIENT rev-parse HEAD)" > $SCRIPT_DIR/import_ref.txt