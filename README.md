# mbed-bootloader

Generic bootloader to be used in conjunction with [Pelion Device Management Client](https://github.com/ARMmbed/mbed-cloud-client).

## Build instructions

1. Install `mbed-cli` https://github.com/ARMmbed/mbed-cli
1. Run `mbed deploy` to pull in dependencies
1. Compile by running `mbed compile -t GCC_ARM -m (K64F|NUCLEO_F429ZI|UBLOX_EVK_ODIN_W2) --profile=tiny.json`

## Installation instructions

An image that contains the bootloader and your application can then be flashed on your device.

If you use Mbed CLI 1.8.x then two images are created when you compile [Pelion Device Management Client example application](https://github.com/ARMmbed/mbed-cloud-client-example).
1. A full image `mbed-cloud-client-example-internal.bin` which combines the application with the bootloader and is used for the initial programming of the device
1. An update image `mbed-cloud-client-example-internal_update.bin` which contains only the application and is used for updating the device over the air

In order for Mbed CLI to pick up the bootloader binary you built, set `"target.bootloader_img": <path to bootloader binary>` in your application's `mbed_app.json` For more details, see [Arm Mbed OS managed bootloader](https://os.mbed.com/docs/v5.10/tutorials/bootloader.html#arm-mbed-os-managed-bootloader).

Flash `mbed-cloud-client-example-internal.bin` to your device by drag and drop.

## Metadata Header

The metadata header is the bootloader update interface. Each stage of the boot sequence leading up to and including the application (except the root bootloader) is paired with a metadata header (containing version, size, hash etc.). Information contained in the metadata header allows validation and ordering of available firmwares.

The firmware metadata header structure can be found [here](https://github.com/ARMmbed/mbed-bootloader/blob/master/modules/metadata-header/update-client-metadata-header/arm_uc_metadata_header_v2.h). There are two header formats, internal and external. The external header format is used for storing firmware on external storage which is assumed to be insecure. Hence the external header format contains extra security information to prevent external tampering of the header data.

## Configurations

NOTE: All these configurations must be set the same in the Pelion Device Management Client when compiling the corresponding application for successful update operation.

### Active Application and Header

1. `update-client.application-details`, Address at which the metadata header of the active firmware is written. **Must align to flash erase boundary**
1. `mbed-bootloader.application-start-address`, Address at which the application starts **Must align to vector table size boundary and flash write page boundary**.
1. `mbed-bootloader.application-jump-address`, Optional address for the application's entry point (vector table) if this is different from `mbed-bootloader.application-start-address`.

If the `application-start-address` is set less than one erase sector after the `update-client.application-details`, the two regions will be erased together. Otherwise the two regions will be erased separately in which case `application-start-address` must also align to **flash erase boundary**.

If `application-jump-address` is not set, the `application-start-address` will be used as the application's entry point. The entry point MUST be the same as "target.mbed_app_start" in the application.

### Firmware Candidate Storage

1. `MBED_CLOUD_CLIENT_UPDATE_STORAGE`, This need to be set in the "macros" section of `mbed_app.json`. Choices are ARM_UCP_FLASHIAP_BLOCKDEVICE and ARM_UCP_FLASHIAP. This determines whether the firmware is stored on a blockdevice or internal flash. If blockdevice is used `ARM_UC_USE_PAL_BLOCKDEVICE=1` must also be set.
1. `update-client.storage-address`, The address in sd block device or internal flash where the firmware candidates are stored. **Must align to flash erase boundary**
1. `update-client.storage-size`, total size on the block device or internal flash reserved for firmware storage. It will be rounded up to align with flash erase sector size automatically.
1. `update-client.storage-locations`, The number of slots in the firmware storage.

NOTE: See the [Pelion Device Management Client documentation](https://cloud.mbed.com/docs/current/porting/update-k64f-port.html) for more information about storage options available and porting to new platforms.

### Device Secret Key

The bootloader uses device secret key to authenticate anything that is stored on external storage. The update client must be able to obtain the same key as the bootloader. The key is derived from a device root of trust using the algorithm [here](https://github.com/ARMmbed/mbed-cloud-client/blob/master/update-client-hub/modules/common/source/arm_uc_crypto.c#L401). If the firmware candidate is stored on internal storage, i.e. `MBED_CLOUD_CLIENT_UPDATE_STORAGE=ARM_UCP_FLASHIAP` then the device secret key is not needed by the bootloader hence any configuration will be ignored.

You may choose to use Mbed OS' KVSTORE feature to store and read the device RoT. During first boot Pelion Device Management Client will generate a random number from an available entropy source and storage it in KVSTORE on internal flash. On subsequent boots, the RoT will be read from KVSTORE. To enable KVSTORE RoT, you must set the following:
1. Set `"mbed-bootloader.use-kvstore-rot": 1` in `mbed_app.json` to enable the KVStore RoT implementation [here](https://github.com/ARMmbed/mbed-bootloader/blob/master/source/kvstore_rot.cpp).
1. Set `"storage.storage_type": "FILESYSTEM"`, this configurations will have RoT stored on internal flash.
1. Set `"storage_filesystem.internal_base_address"`. The addresses **Must align to flash erase boundary**.
1. Set `"storage_filesystem.rbp_internal_size"`. It **must contain even number of sectors**.

Alternatively you can choose to use a custom device specific RoT by implementing the function `mbed_cloud_client_get_rot_128bit`. An example can be found [here](https://github.com/ARMmbed/mbed-bootloader/blob/master/source/example_insecure_rot.c#L40).

### Bootloader Information

Pelion Cloud Client reports some information about the bootloader to the cloud. The bootloader provides this information in the form of a `arm_uc_installer_details_t` struct:
```
const arm_uc_installer_details_t bootloader = {
    .arm_hash = BOOTLOADER_ARM_SOURCE_HASH,
    .oem_hash = BOOTLOADER_OEM_SOURCE_HASH,
    .layout   = BOOTLOADER_STORAGE_LAYOUT
};
```

For this information to propagate to the cloud, the 3 macros (`BOOTLOADER_ARM_SOURCE_HASH`, `BOOTLOADER_OEM_SOURCE_HASH` and `BOOTLOADER_STORAGE_LAYOUT`) in [mbed_bootloader_info.h](https://github.com/ARMmbed/mbed-bootloader/blob/master/source/mbed_bootloader_info.h) need to be populated manually before the bootloader binary is built.

1. `BOOTLOADER_ARM_SOURCE_HASH` should be the SHA-1 git commit hash of the published mbed-bootloader source code.
1. `BOOTLOADER_OEM_SOURCE_HASH` is used to indicate any modification that OEMs have made on top of the vanilla mbed-bootloader. Hence it should be populated with the OEM modified bootloader SHA-1 git commit hash.
1. `BOOTLOADER_STORAGE_LAYOUT` is a proprietary enum to indicate the storage layout supported by this bootloader. The OEM is free to define the meaning of this number.

In order for the cloud client to recognise this struct and obtain the information. The offset of the symbol in the bootloader binary needs to be populated in the cloud client's configuration file:
1. Compile the bootloader. Flash and run the bootloader. On the serial UART you will see the following printout:

    > Layout: <layout_no> <boot_loader_info_address>
1. Keep a note of the `boot_loader_info_address` which we will use in the next step.
1. In the `mbed_app.json` of the Pelion Cloud Client Application, change the following: `"update-client.bootloader-details" : "<boot_loader_info_address>"`

### MISC

User **may** set in `mbed_app.json`:
1. `mbed-bootloader.max-copy-retries`, The number of retries after a failed copy attempt.
1. `mbed-bootloader.max-firmware-locations`, The maximum number of stored firmware candidates.
1. `mbed-bootloader.max-boot-retries`, The number of retries after a failed forward to application.
1. `mbed-bootloader.show-progress-bar`, Set to 1 to print a progress bar for various processes.
1. `mbed-bootloader.max-application-size`, Maximum size of the active application. The default value is `FLASH_START_ADDRESS + FLASH_SIZE - APPLICATION_START_ADDRESS`. Bootloader uses this value to reject candidate image that are too large.
1. `mbed-bootloader.flash-start-address`, Used to calculate default value of `max-application-size` and help define other macros. Value for common platforms are already given in [`mbed_lib.json`](mbed_lib.json)
1. `mbed-bootloader.flash-size`, Used to calculate default value of `max-application-size` and help define other macros. Value for common platforms are already given in [`mbed_lib.json`](mbed_lib.json)

## Flash Layout

### The flash layout for K64F with KVStore and firmware storage on internal flash

```
    +--------------------------+
    |                          |
    |                          |
    |Firmware Candidate Storage|
    |                          |
    |                          |
    |                          |
    +--------------------------+ <-+ update-client.storage-address
    |         KVSTORE          |
    +--------------------------+ <-+ storage_tdb_internal.internal_base_address
    |                          |
    |                          |
    |                          |
    |        Active App        |
    |                          |
    |                          |
    |                          |
    +--------------------------+ <-+ mbed-bootloader.application-start-address
    |                          |
    |Active App Metadata Header|
    |                          |
    +--------------------------+ <-+ update-client.application-details
    |                          |
    |        Bootloader        |
    |                          |
    +--------------------------+ <-+ 0
```

### Notes on Flash Layout

- Internal Flash Only layout can be enabled by compiling the bootloader with the configuration file `--app-config configs/internal_flash_no_rot.json`. By default the firmware storage region and filesystem is on [external sd card](#external-storage).
- The default flash layout is tested with GCC_ARM compiler and tiny.json compiler profile only. If a different compiler is used, the bootloader binary size will be larger and the offsets needs to be adjusted.
- The KVSTORE regions require even number of flash erase sectors. If the firmware candidate is stored on internal flash, the bootloader does not access the KVStore. But it still needs to be there for the benefit of the Pelion Device Management Client.
- Some micro-controller chips are designed with 2 banks of flash that can be read from and written to independently from each other. Hence it is a good idea to put your bootloader and active application on bank 1, your kvstore and firmware candidate storage on bank 2. This way when the application writes data to flash, it doesn't need to halt the processor execution to do it.

### Alignment

**Flash Erase Boundary**: Flash can usually only be erased in blocks of specific sizes, this is platform specific and hence many regions need to align to this boundary.

**Flash Page Boundary**: Flash can usually only be written in blocks of specific sizes, this is platform specific and hence many regions need to align to this boundary.

**Vector Table Size Boundary**: The ARM architecture dictates that the Vector table of the application must be placed at an address that aligns to the next power of 2 of the size of the vector table.

## External Storage

The firmware update candidates is stored on an external sd card if the default configuration is used. The firmware is stored sequentially on the block device. The expected layout is as follows:
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
    +--------------------------+ <-+ Start of SD card block device (i.e. 0x0)
```

## Debug

Debug prints can be turned on by enabling the define `#define tr_debug(fmt, ...) printf("[DBG ] " fmt "\r\n", ##__VA_ARGS__)` in `source/bootloader_common.h` and setting the `ARM_UC_ALL_TRACE_ENABLE=1` macro on command line `mbed compile -DARM_UC_ALL_TRACE_ENABLE=1`.

## Example config case study

Scenario: Your target is NUCLEO_F429ZI. You have added extra functionality to the bootloader such that the size of the bootloader exceeded the default 32KiB. How to configure your bootloader and application so that everything still work together.

### STEP 1: Design flash layout

NUCLEO_F429ZI has 2MiB of flash, and its sector sizes are as follows: 4x16KiB, 1x64KiB, 7x128KiB, 4x16KiB, 1x64KiB, 7x128KiB.
Because the bootloader is larger than 32KiB, it will take the first 3 sectors. The KVStore area can no longer take 2x16KiB sectors. KVStore require even number of sectors. Hence we will move KVSTORE to the last 2x128KiB sectors in the flash region. So we will end up with the following layout:

```
0x08000000 - 0x0800C000 Bootloader
0x0800C000 - 0x0800C400 Application Header
0x0800C400 - 0x081C0000 Application
0x081C0000 - 0x08200000 KVSTORE
```

The update firmware candidate is still stored on sd-card.

### STEP 2: Configure the bootloader

Given the above flash layout the following configuration need to change in the mbed_app.json:

1. `"storage_filesystem.internal_base_address": "(0x08000000+(2*1024-2*128)*1024)"`
1. `"storage_filesystem.rbp_internal_size": "(2*128*1024)"`
1. `"update-client.application-details": "(0x08000000+3*16*1024)"`
1. `"mbed-bootloader.application-start-address": "(0x08000000+(3*16+1)*1024)"`
1. `"mbed-bootloader.max-application-size" : "((1024*2-128*2-3*16-1)*1024)"`

Now compile your bootloader. Flash and run the bootloader, on the serial UART you will see the following printout:

> Layout: <layout_no> <boot_loader_info_address>

Keep a note of the `boot_loader_info_address` which we will use in the next step.

### STEP 3: Configure the Pelion Cloud Client Application

In mbed_app.json, change the following:

1. `"update-client.application-details" : "(0x08000000+3*16*1024)"`
1. `"update-client.bootloader-details" : "<boot_loader_info_address>"`

Change the following in mbed_app.json:

1. `"storage_filesystem.internal_base_address": "(0x08000000+(2*1024-2*128)*1024)"`
1. `"storage_filesystem.rbp_internal_size": "(2*128*1024)"`
1. `"target.app_offset": "0x800c400",`
1. `"target.header_offset": "0x800c000",`
1. `"target.bootloader_img": "<path_to_your_newly_built_image>"`

Now you can build the application following the [Pelion Device Management Platform Documentation](https://cloud.mbed.com/docs/current/updating-firmware/updating-end-to-end-tutorials.html).
