# mbed-bootloader

Generic bootloader to be used in conjunction with [Pelion Device Management Client](https://github.com/ARMmbed/mbed-cloud-client).
Mbed-bootloader can be used with FW application that is not build built with arbitrary embedded OS.

The bootloader and FW application must share the following configurations:
1. FW metadata format
2. Internal Flash layout
   1. FW metadata header address
   2. FW application address to be loaded
   3. KVStore - base address and size.
3. KVStore binary layout - KVStore data written from the application must be readable from bootloader, thus KVStore versions must be binary format compatible.

## Flash layout
Before building a bootloader internal flash layout should be defined:

An example layout can look like:
```
    +--------------------------+
    |                          |
    |                          |
    |                          |
    |Firmware Candidate Storage|
    |                          |
    |                          |
    |                          |
    +--------------------------+ <-+ fota.storage-start-address
    |                          |
    |         KVSTORE          |
    |                          |
    +--------------------------+ <-+ storage_tdb_internal.internal_base_address
    |                          |
    |                          |
    |                          |
    |        FW image          |
    |                          |
    |                          |
    |                          |
    +--------------------------+ <-+ mbed-bootloader.application-start-address
    |     FW Metadata header   |
    +--------------------------+ <-+ mbed-bootloader.application-header-address
    |                          |
    |        Bootloader        |
    |                          |
    +--------------------------+ <-+ 0 (Flash base address)
```
Layout considerations:
- `mbed-bootloader.application-header-address` must be aligned to internal flash erase block size
- `mbed-bootloader.application-start-address` must be aligned to the size of the vector table extended to the next larger power of 2.  
  The size of vector table equals to the total number of interrupt sources (including system exceptions) interrupts * 4 (bytes for each vector).
- `storage_tdb_internal.internal_base_address` (only relevant when KVStore is configured to be in internal flash).  
  The address must be aligned to internal flash erase block size.
- `storage_tdb_internal.internal_size` - KVStore size must be at least 2 erase block size.
- `fota.storage-start-address` must be aligned to internal flash erase block size.
- KVStore should be located after (higher addresses) than FW images, for the sake of not overwriting it while programming `.bin` files.

Flash layout should correspond to bootloader and FW application linker scripts / scatter files.

## FW Metadata header

FW metadata header contains an information used by bootloader for validating FW image before loading it.
FW metadata header includes:
- FW version - used both by application and bootloader
  - FOTA library built as part of FW application reports FW version to Pelion device management portal
  - bootloader asserting FW version when installing the candidate for preventing rollbacks.
- FW size & digest
- May also include ECDSA raw signature in case bootloader and application were built to support it.

FW Metadata header is created by mbed-os post-build scripts while creating a combined image containing bootloader, FW metadata header and FW image.
For non mbed-os builds [pdm-sign tool][1] shall be used.

For mbed-os builds the FW metadata header is defined via `mbed_app.json` file in the application build.

## Build instructions

Bootloader is build for each target using preset directory structure:
```
presets/
├── TARGET_DISCO_F769NI
│   └── TARGET_BL_INTERNAL_FLASH
│       ├── mbed_app.json
│       └── mbed_lib.json.template
├── TARGET_DISCO_L475VG_IOT01A
│   └── TARGET_BL_INTERNAL_FLASH
│       ├── mbed_app.json
│       └── mbed_lib.json.template
├── TARGET_K64F
│   └── TARGET_BL_INTERNAL_FLASH
│       ├── mbed_app.json
│       └── mbed_lib.json.template
├── TARGET_NRF52840_DK
│   └── TARGET_BL_INTERNAL_FLASH
│       ├── mbed_app.json
│       └── mbed_lib.json.template
├── build_presets.py
└── export.py
```
Under `presets` directory you can find target directories for each compilation target. Under each target directory you can find configuration directory.
Each target directory can have more than one configuration directories - e.g. for storing FOTA candidate either under internal flash or SPI flash.
Each configuration directory contains mbed_app.json file for building the bootloader for current configuration. In addition it contains `mbed_lib.json.template` file.
Once expanded, these template files should be added to application build and will inject all the relevant configurations to the application build. E.g. application FW and FW metadata header addresses, KVStore address and size, e.t.c.

On a clean workspace execute:
```
mbed deploy --protocol ssh
pip install -r mbed-os/requirements.txt
python3 presets/build_presets.py
```
build_presets.py script will build all the presets under presets directory and expand the `mbed_lib.json` templates.


once presets are built export them to the FW application by calling `python3 export.py {dir}` script where `{dir}` is a directory under FW application.
For example: `python3 export.py ~/pelion-client-lite-example/prebuilt-bl`

In the application's `mbed_app.json` file add the relevant bootloader configuration preset. e.g. `"target.extra_labels_add": ["BL_INTERNAL_FLASH"]` this will make sure mbed-os build system's source scan will go in to this directory and find both bootloader binary and `mbed_lib.json` file with the relevant configs.

> Note: Make sure that `BOOTLOADER` feature is not enabled for the target via `target.features_add` in `mbed_app.json`

Build the application FW by calling `mbed compile -m ...` command


## Creating custom presets

TO create a custom preset, add relevant target directory. Under target directory create a preset directory with a name `TARGET_{name}` where name is the preset name.
create mbed_app.json file and corresponding `mbed_lib.json.template` files.

Following configurations/tweaks can be considered:
- `"fota.block-device-type"` for specifying the type of a block device for reading the FOTA candidate from. Options are:
  - `FOTA_INTERNAL_FLASH_BD` - candidate is stored in internal flash
  - `FOTA_CUSTOM_BD` - custom block device can be used for setting with SPIF or SD card block devices. In this case make sure bootloader sources have a valid implementation for `mbed::BlockDevice *fota_bd_get_custom_bd()` getter function. If not - create one.
  - `FOTA_EXTERNAL_BD` - custom block device, bootloader need to implement fota block device interface given by `fota_block_device.h` header file.
- `"fota.storage-start-address"` - base address for FOTA candidate.
- `"fota.storage-size"` - candidate region size in a given block device
- `"fota.encryption-support"` - specify whether candidate is encrypted or not
- `"fota.candidate-block-size"` - candidate is segmented in to blocks - specify block size
- `"fota.fi-mitigation-enable"` - enable FI mitigation code - produces bigger code size
- `"fota.resume-support"` - specify FOTA candidate format. In case support is enabled FOTA candidate will contain metadata interleaved within the candidate.
- `MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT` - when set instructs bootloader to verify ECDSA signature over FW image. The signature is expected to be found in FW metadata header (both current one and in the candidate).

Make sure to align these configurations between the application and bootloader builds.

[1]: TODO:some-tool-must-be-available-if-not-create-one 