#!/usr/bin/env python3
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

import logging
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger('preset-builder')

BUILD_CMD_TEMPLATE = 'mbed compile' \
            ' -m {target} -t {toolchain}' \
            ' --profile release --app-config {config}'

def get_tag(root_dir: Path):
    tag = subprocess.check_output(
        ['git', 'tag', '--points-at', 'HEAD'],
        cwd=root_dir.as_posix()
    ).decode().strip()
    if tag:
        return tag.split('\n')[0]
    sha = subprocess.check_output(
        ['git', 'rev-parse', '--short', 'HEAD'],
        cwd=root_dir.as_posix()
    ).decode().strip()
    return sha


def main():
    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.INFO
    )

    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent
    tag = get_tag(root_dir)
    user_target = None
    if len(sys.argv) > 1:
        user_target = sys.argv[1]
    for target in script_dir.iterdir():
        target_name = target.name.lstrip('TARGET_')
        if user_target and user_target != target_name:
            continue
        if not target.is_dir():
            continue
        for preset in target.iterdir():
            app_config = preset.joinpath('mbed_app.json').relative_to(root_dir)
            # DISCO_L475VG_IOT01A and NUCLEO_F411RE compiled with ARMC6 to decrease the code size
            if (target_name == "NUCLEO_F411RE" or target_name == "DISCO_L475VG_IOT01A"):
                cmd = BUILD_CMD_TEMPLATE.format(
                    target=target_name, toolchain="ARM", config=app_config.as_posix()).split(' ')
            else:
                cmd = BUILD_CMD_TEMPLATE.format(
                    target=target_name, toolchain="GCC_ARM", config=app_config.as_posix()).split(' ')
            log.info(
                'Building %s with preset %s:\n%s\n%s\n%s',
                target_name, preset.name,
                '-' * 80, ' '.join(cmd), '-' * 80
            )
            subprocess.check_call(cmd, cwd=root_dir.as_posix())
            build_dir = root_dir / 'BUILD' / target_name / 'GCC_ARM-RELEASE'
            extensions = ['.bin', '.hex']
            artifacts = filter(
                lambda p: p.suffix in extensions,
                build_dir.glob('mbed-bootloader.*')
            )
            
            for artifact in artifacts:
                shutil.copyfile(
                    artifact.as_posix(),
                    preset.joinpath(
                        'mbed-bootloader-{tag}{suffix}'.format(
                            tag=tag, suffix=artifact.suffix)
                    ).as_posix()
                )

            mbed_lib_template = preset / 'mbed_lib.json.template'
            template = mbed_lib_template.read_text()
            config = template.format(
                target=target_name,
                tag=tag,
                preset=preset.name
            )
            mbed_lib_file = mbed_lib_template.with_suffix('')
            mbed_lib_file.write_text(config)


if __name__ == "__main__":
    main()
