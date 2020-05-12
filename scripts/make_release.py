#!/usr/bin/env python
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Ltd.
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

import re, os
from subprocess import check_output, call

from intelhex import IntelHex

# format: "config_name": ("config_file_name", "storage-option", "rot-option")
bootloader_configs = {
    "kvstore_and_fw_candidate_on_sd": (
        "configs/kvstore_and_fw_candidate_on_sd.json", "block-device", "fake-rot"
    ),
    "internal_flash_no_rot": (
        "configs/internal_flash_no_rot.json", "internal-flash", "no-rot"
    ),
    "internal_kvstore_with_sd": (
        "configs/internal_kvstore_with_sd.json", "internal-flash", "sd-update"
    ),
    "psa": (
        "configs/psa.json", "block-device", "psa"
    ),
    "internal_kvstore_with_qspif": (
        "configs/internal_kvstore_with_qspif.json", "internal-kvstore", "qspif"
    ),
    "internal_kvstore_with_spif": (
        "configs/internal_kvstore_with_spif.json", "internal-kvstore", "spif"
    )
}
# format: ("target", "config_name")
targets = [
    ("K64F", "kvstore_and_fw_candidate_on_sd"),
    ("K64F", "internal_flash_no_rot"),  # cloud client
    ("K64F", "internal_kvstore_with_sd"),  # cloud client
    ("K66F", "internal_flash_no_rot"),  # cloud client
    ("NUCLEO_L4R5ZI", "internal_flash_no_rot"),  # cloud client
    ("NUCLEO_F429ZI", "internal_flash_no_rot"),  # cloud client
    ("NRF52840_DK", "internal_kvstore_with_qspif"),
    ("NUCLEO_F411RE", "kvstore_and_fw_candidate_on_sd"),  # cloud client
    ("DISCO_L475VG_IOT01A", "internal_kvstore_with_qspif"),  # cloud client
    ("LPC55S69_NS", "psa"),  # cloud client
    ("NUCLEO_F303RE", "internal_kvstore_with_spif"),  # cloud client
    ("DISCO_F769NI", "internal_flash_no_rot")
]
toolchain = "GCC_ARM"
profile = "release"  # default value, changed via command line arg --profile
bootloader_repo_name = os.path.basename(os.getcwd())

def check_clean():
    cmd = "git status --untracked-files=no --porcelain"
    output = check_output(cmd).decode('utf-8')
    if output == '':
        return True
    else:
        return False

def get_sha1():
    cmd = "git rev-parse HEAD"
    return check_output(cmd.split()).strip().decode('utf-8')

def get_git_desc():
    cmd = "git fetch --tags"
    call(cmd.split())
    cmd = "git describe --tags --abbrev=4"
    return check_output(cmd.split()).strip().decode('utf-8')

def patch_version():
    """
    Parse for the current git commit and put it into `mbed_bootloader_info.h`
    """
    sha1 = get_sha1()
    print(sha1)
    sha1_list = [sha1[i:i + 2] for i in range(0, len(sha1), 2)]
    with open("./source/mbed_bootloader_info.h", 'r+') as fd:
        s = ""
        replace_first_line = True
        flag_inside_source_hash = False
        for line in fd:
            if line.startswith("#define BOOTLOADER_ARM_SOURCE_HASH {"):
                flag_inside_source_hash = True

            elif line.startswith("}"):
                flag_inside_source_hash = False

            elif line.strip().startswith("0x") and flag_inside_source_hash:
                if replace_first_line:
                    line = ('    ' + '0x{}, ' * 10 + '\\\n').format(*sha1_list)
                    replace_first_line = False
                else:
                    line = ('    ' + '0x{}, ' * 9 + '0x{}  \\\n') \
                                .format(*sha1_list[10:])

            s += line

        fd.seek(0)
        fd.write(s)
        fd.truncate()

def find_offset(map_file, symbol):
    """
    Find offset of symbol given a map files
    """
    with open(map_file, 'r') as fd:
        s = fd.read()

    regex = r"\.rodata\..*{}\s+(0x[0-9a-fA-F]+)".format(symbol)
    match = re.search(regex, s, re.MULTILINE)
    offset = int(match.groups()[0], 16)

    if offset == 0:
        raise Exception("Symbol {} was found in linker file, but it was not added (offset 0).".format(symbol))

    return offset

def mergehex(fn_1, fn_2):
    """
    merge two hex files write back to file 1.
    """
    ih_1 = IntelHex(fn_1)
    ih_2 = IntelHex(fn_2)
    ih_1.merge(ih_2)

    ih_1.tofile(fn_1, format='hex')

if __name__ == '__main__':
    import shutil, os, glob, json, pprint, argparse, sys
    from collections import OrderedDict
    from os import path

    parser = argparse.ArgumentParser(
        description='Build and copy bootloader binary into example' + \
                    ' application and modify config file')

    # specify arguments
    parser.add_argument('-o', '--output', required=True,
                        help='Path to top level example application')

    parser.add_argument('-p', '--profile', required=False,
                        help='Compiler profile for mbed os')

    parser.add_argument('-m', '--mcu', required=False,
                        choices=set([x[0] for x in targets]),
                        help='If mcu is set only this mcu will be ' +
                             'released. Must set --config as well')

    parser.add_argument('-c', '--config', required=False,
                        choices=bootloader_configs.keys(),
                        help='If config is set only this config will be ' +
                             'released. Must set --mcu as well')

    parser.add_argument('--prebuilt', action='store_true',
                        help='Use prebuild binaries in CI')
    parser.add_argument('--patch', action='store_true',
                        help='Just prepare the sources for release. Skip build')

    # workaround for http://bugs.python.org/issue9694
    parser._optionals.title = "arguments"

    # get and validate arguments
    args = parser.parse_args()

    # Validate the output path
    if path.isdir(args.output):
        result_dir = args.output
    else:
        print(args.output, "is not a readable directory")
        sys.exit(1)

    # validate --target and --config
    if bool(args.mcu) != bool(args.config):
        print("--mcu and --config must be set together")
        print("="*60)
        parser.print_help()
        sys.exit(1)
    elif args.mcu and args.config:
        targets = [(args.mcu, args.config)]

    # change default compiler profiles if specified
    if args.profile:
        profile = args.profile

    # write SHA1 into mbed_bootloader_info.h
    patch_version()

    if args.patch:
        sys.exit(0)

    with open(path.join(result_dir, "results.txt"), "w") as result_file:
        # loop over all targets
        for target, bootloader_config_name in targets:
            bootloader_config_fn = bootloader_configs[bootloader_config_name][0]
            if not args.prebuilt:
                # compile bootloader
                cmd = "mbed compile -m {} -t {} --profile={} --app-config={}"
                cmd = cmd.format(target, toolchain, profile, bootloader_config_fn)
                print(cmd)
                call(cmd.split())

                if profile == "develop" or profile == "develop.json":
                    build_dir = "./BUILD/{}/{}/".format(target, toolchain)
                else:
                    build_dir = "./BUILD/{}/{}-{}/".format(target, toolchain, profile.split(".")[0].upper())
            else:
                # Binaries generated by CI job
                build_dir = "./BUILD/{}/{}/{}/".format(bootloader_config_name, target, toolchain)

            map_file = path.join(build_dir, bootloader_repo_name + '_application.map')

            bin_file_type = "bin"
            if target == "NRF52840_DK" or target == "LPC55S69_NS":
                bin_file_type = "hex"
            bin_file = path.join(build_dir, bootloader_repo_name + '.' + bin_file_type)

            # find bootloader details offset
            bootloader_offset = find_offset(map_file, "bootloader")
            print("bootloader details address", hex(bootloader_offset))

            # copy binary
            target_name = target.lower().replace('-', '_')
            bootloader_storage = bootloader_configs[bootloader_config_name][1]
            bootloader_storage = bootloader_storage.replace('-', '_')
            bootloader_rot = bootloader_configs[bootloader_config_name][2]
            git_desc = get_git_desc()
            release_desc = git_desc.replace('.', '_')

            fn = 'mbed-bootloader-{}-{}-{}-{}.{}'.format(
                target_name, bootloader_storage, bootloader_rot,
                release_desc, bin_file_type)
            dst = path.join(result_dir, fn)

            if target == "NRF52840_DK":
                print("merging uicr with bootloader")
                # merge bootloader with uicr
                uicr_fn = "configs/uicr-0x74000.hex"
                mergehex(bin_file, uicr_fn)

            print(dst, path.isfile(dst))
            shutil.copyfile(bin_file, dst)

            result_file.write("{} - {} - {}\n".format(fn, hex(bootloader_offset), bootloader_config_fn))
