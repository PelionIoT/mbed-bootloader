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

log = logging.getLogger('preset-exporter')

exported_patterns = ['mbed_lib.json', 'mbed-bootloader-*.*']


def main():
    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.INFO
    )

    script_dir = Path(__file__).resolve().parent
    try:
        export_dir = Path(sys.argv[1])
    except IndexError:
        raise SystemError('path to exported directory must be provided')

    for target in script_dir.iterdir():
        if not target.is_dir():
            continue
        for preset in target.iterdir():
            log.info('Exporting %s with preset %s', target.name, preset.name)
            dest_dir = export_dir / target.name / preset.name
            if dest_dir.is_dir():
                for f in dest_dir.iterdir():
                    f.unlink()
            else:
                dest_dir.mkdir(parents=True)
            for pattern in exported_patterns:
                for artifact in preset.glob(pattern):
                    shutil.copy(
                        artifact.as_posix(),
                        dest_dir.as_posix()
                    )


if __name__ == "__main__":
    main()
