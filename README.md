# mbed-bootloader

Generic bootloader to be used in conjunction with [mbed-cloud-client](https://github.com/ARMmbed/mbed-cloud-client).

## Build instructions

1. Install `mbed-cli` https://github.com/ARMmbed/mbed-cli
1. Run `mbed deploy` to pull in dependencies
1. Compile by running `mbed compile -t GCC_ARM -m (K64F|NUCLEO_F429ZI|UBLOX_EVK_ODIN_W2) --profile=tiny.json`
1. Use this [script](https://github.com/ARMmbed/mbed-cloud-client-example/blob/master/tools/combine_bootloader_with_app.py) to combine the bootloader with application `python tools/combine_bootloader_with_app.py -a {application.bin} -b {bootloader.bin} --app-offset {application-start-address} --header-offset {firmware_metadata_header_address} -o {combined.bin}`.
1. Flash `{combined.bin}` to device by drag and drop.

## Metadata Header

The metadata header is the bootloader update interface. Each stage of the boot sequence leading up to and including the application (except the root bootloader) is paired with a metadata header (containing version, size, hash etc.). Information contained in the metadata header allows validation and ordering of available firmwares.

The firmware metadata header structure can be found [here](https://github.com/ARMmbed/mbed-cloud-client/blob/master/update-client-hub/modules/common/update-client-common/arm_uc_metadata_header_v2.h). There are two header formats, internal and external. The external header format is used for storing firmware on external storage which is assumed to be insecure. Hence the external header format contains extra security information to prevent external tampering of the header data.

## Configurations

NOTE: All these configurations must be set the same in the mbed cloud client when compiling the corresponding application for successful update operation.

### Active Application and Header

1. `update-client.application-details`, Address at which the metadata header of the active firmware is written. **Must align to flash erase boundary**
1. `application-start-address`, Address at which the application starts **Must align to vector table size boundary and flash write page boundary**.
1. `application-jump-address`, Optional address for the application's entry point (vector table) if this is different from `application-start-address`.

If the `application-start-address` is set less than one erase sector after the `update-client.application-details`, the two regions will be erased together. Otherwise the two regions will be erased separately in which case `application-start-address` must also align to **flash erase boundary**.

If `application-jump-address` is not set, the `application-start-address` will be used as the application's entry point. The entry point MUST be the same as "target.mbed_app_start" in the application.

### Firmware Candidate Storage

1. `MBED_CLOUD_CLIENT_UPDATE_STORAGE`, This need to be set in the "macros" section of `mbed_app.json`. Choices are ARM_UCP_FLASHIAP_BLOCKDEVICE and ARM_UCP_FLASHIAP. This determines whether the firmware is stored on a blockdevice or internal flash. If blockdevice is used `ARM_UC_USE_PAL_BLOCKDEVICE=1` must also be set. If SPI Flash is used for update client storage, please define the macro MBED_CONF_UPDATE_CLIENT_STORAGE_SPIF. If SD card is used for update client storage, please define thhe macro MBED_CONF_UPDATE_CLIENT_STORAGE_SD. If both of the macros are not defined, the bootloader will choose SD card by default.
1. `update-client.storage-address`, The address in SD block device, SPI flash or internal flash where the firmware candidates are stored. Please note that if the storage is SPI flash, the storage address indexing starts from 0x0. For example, if you would like to let Update Client access the SPI flash starting from its 2MB position, please specify "(1024*1024*2)". **Must align to flash erase boundary**
1. `update-client.storage-size`, total size on the block device or internal flash reserved for firmware storage. It will be rounded up to align with flash erase sector size automatically.
1. `update-client.storage-locations`, The number of slots in the firmware storage.
1. `update-client.storage-page`, The write page size of the underlying storage.

NOTE: See the [mbed cloud client documentation](https://cloud.mbed.com/docs/current/porting/update-k64f-port.html) for more information about storage options avaiable and porting to new platforms.

### Device Secret Key

The bootloader uses device secret key to authenticate anything that is stored on external storage. The update client must be able to obtain the same key as the bootlaoder. The key is derived from a device root of trust using the algorithm [here](https://github.com/ARMmbed/mbed-cloud-client/blob/master/update-client-hub/modules/common/source/arm_uc_crypto.c#L401).

You may choose to use NVSTORE to store the device RoT. During first boot mbed cloud client will generate a random number from an available entropy source and storge it in NVSTORE on internal flash. On subsequent boots, the RoT will be read from NVSTORE. To enable NVSTORE RoT, you must set the following:
1. Macro `ARM_BOOTLOADER_USE_NVSTORE_ROT=1` to enable the RoT implementation [here](https://github.com/ARMmbed/mbed-bootloader/blob/master/source/nvstore_rot.cpp).
1. "nvstore.area_1_address", "nvstore.area_1_size", "nvstore.area_2_address", "nvstore.area_2_size". The addresses **Must align to flash erase boundary**. The sizes must be full sector sized and at least 1k.
1. NVSTORE and SOTP are binary compatible hence the bootloader works with any software that uses SOTP as long as the offsets are set the same.

Alternatively you can choose to use a custom device specific RoT by implementing the function `mbed_cloud_client_get_rot_128bit`. An example can be found [here](https://github.com/ARMmbed/mbed-bootloader/blob/master/source/example_insecure_rot.c#L40).

### MISC

User **may** set in `mbed_app.json`:
1. `MAX_COPY_RETRIES`, The number of retries after a failed copy attempt.
1. `MAX_FIRMWARE_LOCATIONS`, The maximum number of stored firmware candidates.
1. `MAX_BOOT_RETRIES`, The number of retries after a failed forward to application.
1. `SHOW_PROGRESS_BAR`, Set to 1 to print a progress bar for various processes.

## Flash Layout

### The flash layout for K64F with SOTP and firmware storage on internal flash

```
    +--------------------------+
    |         LittleFS         |
    |     (Does not concern    |
    |        Bootloader)       |     update-client.storage-address
    +--------------------------+ <-+              +
    |                          |     update-client.storage-size
    |                          |
    |                          |
    |Firmware Candidate Storage|
    |                          |
    |                          |
    |                          |
    +--------------------------+ <-+ update-client.storage-address
    |                          |
    |                          |
    |                          |
    |        Active App        |
    |                          |
    |                          |
    |                          |
    +--------------------------+ <-+ application-start-address
    |                          |
    |Active App Metadata Header|
    |                          |
    +--------------------------+ <-+ update-client.application-details
    |        NVSTORE_2         |
    +--------------------------+ <-+ nvstore.area_2_address
    |        NVSTORE_1         |
    +--------------------------+ <-+ nvstore.area_1_address
    |                          |
    |        Bootloader        |
    |                          |
    +--------------------------+ <-+ 0
```

### Notes on Flash Layout

- Internal Flash Only layout can be enabled by compiling the bootloader with the internal_flash_sotp.json configuration file `--app-config configs/internal_flash_sotp.json`. By default the firmware storage region and filesystem is on [external sd card](#external-storage).
- The default flash layout is tested with GCC_ARM compiler and tiny.json compiler profile only. If a different compiler is used, the bootloader binary size will be larger and the offsets needs to be adjusted.
- The NVSTORE regions require 1 flash erase sector each with at least 1k of space.
- The LittleFS requires 2 flash sectors per folder and 1 sector per file as well as 2 sectors for the filesystem itself.

### Alignment

**Flash Erase Boundary**: Flash can usually only be erased in blocks of specific sizes, this is platform specific and hence many regions need to align to this boundary.

**Flash Page Boundary**: Flash can usually only be written in blocks of specific sizes, this is platform specific and hence many regions need to align to this boundary.

**Vector Table Size Boundary**: The ARM architecture dictates that the Vector table of the application must be placed at an address that aligns to the next power of 2 of the size of the vector table.

## External Storage

The firmware update candidates can be stored on an external sd card. The firmware is stored sequentially on the block device. The expected layout is as follows:
```
    +--------------------------+<-+ End of SD card block device
    |                          |
    +--------------------------+<-+ update-client.storage-size + update-client.storage-address
    |                          |
    +--------------------------+
    |                          |
    |   Firmware Candidate 1   |
    |                          |
    +--------------------------+
    |   Firmware Candidate 1   |
    |     Metadata Header      |
    +--------------------------+
    |                          |
    +--------------------------+
    |                          |
    |   Firmware Candidate 0   |
    |                          |
    +--------------------------+
    |   Firmware Candidate 0   |
    |     Metadata Header      |
    +--------------------------+ <-+ update-client.storage-address
    |                          |
    +--------------------------+ <-+ Start of SD card block device (ie 0x0)
```

## Debug

Debug prints can be turned on by enabling the define `#define tr_debug(fmt, ...) printf("[DBG ] " fmt "\r\n", ##__VA_ARGS__)` in `source/bootloader_common.h` and setting the `ARM_UC_ALL_TRACE_ENABLE=1` macro on command line `mbed compile -DARM_UC_ALL_TRACE_ENABLE=1`.
