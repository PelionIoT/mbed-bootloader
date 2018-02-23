# mbed-bootloader

Generic bootloader to be used in conjunction with [mbed-cloud-client](https://github.com/ARMmbed/mbed-cloud-client-restricted).

For an overview of high-level requirements of the bootloader, refer to [this document](docs/requirements.md).
For pseudo-code of the bootloader, refer to [this document](docs/pseudo-code.md).

The interface between the bootloader and an 'update-client' have been described [here](docs/update-interface.md).

## Build instructions

1. Install `mbed-cli` https://github.com/ARMmbed/mbed-cli
1. Run `mbed deploy` to pull in dependencies
1. Compile by running `mbed compile -t GCC_ARM -m (K64F|NUCLEO_F429ZI|UBLOX_EVK_ODIN_W2) --profile=tiny.json`
1. Use this [script](https://github.com/ARMmbed/mbed-cloud-client-example/blob/master/tools/combine_bootloader_with_app.py) to combine the bootloader with application `python tools/combine_bootloader_with_app.py -a {application.bin} -b {bootloader.bin} --app-offset {firmware_metadata_header_address+firmware_metadata_header_size} --header-offset {firmware_metadata_header_address} -o {combined.bin}`.
1. Flash `{combined.bin}` to device by drag and drop.

## Configurations

User **must** set in `mbed_app.json`:
1. `update-client.application-details`, Address at which the metadata header of the active firmware is written. **Must align to flash erase boundary**
1. `application-start-address`, Address at which The application starts **Must align to vector table size boundary and flash write page boundary**. It is assumed the region between `update-client.application-details` and `application-start-address` contains only the header. MUST be the same as "target.mbed_app_start" in the application.
1. `update-client.storage-address`, The address in sd block device or internal flash where the firmware candidates are stored. **Must align to flash erase boundary**
1. `update-client.storage-size`, total size on the block device or internal flash reserved for firmware storage. It will be rounded up to align with flash erase sector size automatically.
1. `update-client.storage-locations`, The number of slots in the firmware storage.
1. `update-client.storage-page`, The write page size of the underlying storage.

If you are using SOTP to provide the RoT, you must set the following:
- "sotp-section-1-address", "sotp-section-1-size", "sotp-section-2-address", "sotp-section-2-size"
The addresses **Must align to flash erase boundary**. The sizes must be full sector sized and at least 1k large.

All these configurations must be set the same in the mbed cloud client when compiling the corresponding application for successful update operation.

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
    |          SOTP_2          |
    +--------------------------+ <-+ sotp-section-2-address
    |          SOTP_1          |
    +--------------------------+ <-+ sotp-section-1-address
    |                          |
    |        Bootloader        |
    |                          |
    |                          |
    +--------------------------+ <-+ 0
```

### Notes on Flash Layout
- Internal Flash Only layout can be enabled by compiling the bootloader with the internal_flash_sotp.json configuration file `--app-config configs/internal_flash_sotp.json`. By default the firmware storage region and filesystem is on [external sd card](#external-storage).
- The default flash layout is tested with GCC_ARM compiler and tiny.json compiler profile only. If a different compiler is used, the bootloader binary size will be larger and the offsets needs to be adjusted.
- The SOTP regions require 1 flash erase sector each with at least 1k of space.
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
