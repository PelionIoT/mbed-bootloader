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
DST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR="$CLOUD_CLIENT/fota"

declare -a FOTA_FILES=(
        "fota_base.h"
        "fota_block_device.h"
        "fota_candidate.c"
        "fota_candidate.h"
        "fota_component.c"
        "fota_component_defs.h"
        "fota_component.h"
        "fota_component_internal.h"
        "fota_config.h"
        "fota_crypto.c"
        "fota_crypto_defs.h"
        "fota_crypto.h"
        "fota_header_info.h"
        "fota_header_info_v3.c"
        "fota_internal.h"
        "fota_nvm.h"
        "fota_nvm_int.h"
        "fota_platform_hooks.h"
        "fota_platform_hooks_default.c"
        "fota_status.h"
        "platform/nxp/fota_block_device_nxp_lpc.cpp"
        "platform/mbed-os/fota_block_device_mbed_os.cpp"
        "mbed_lib.json"
)

shopt -s extglob
rm -fr $DST_DIR/!(*.sh)

for file in "${FOTA_FILES[@]}"
do
    SRC_FILE="$SRC_DIR/$file"
    DST_FILE="$DST_DIR/$file"
    mkdir -p `dirname $DST_FILE`
    cp -v $SRC_FILE $DST_FILE
done

echo "Imported from mbed-cloud-client-internal at hash: $(git -C $CLOUD_CLIENT rev-parse HEAD)" > $DST_DIR/import_ref.txt
