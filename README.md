# mbed-bootloader

Generic bootloader to be used in conjunction with [mbed-cloud-client](https://github.com/ARMmbed/mbed-cloud-client-restricted).

For an overview of high-level requirements of the bootloader, refer to [this document](docs/requirements.md).
For pseudo-code of the bootloader, refer to [this document](docs/pseudo-code.md).

The interface between the bootloader and an 'update-client' have been described [here](docs/update-interface.md).

## Build instructions

1. Install `mbed-cli` https://github.com/ARMmbed/mbed-cli
1. Run `mbed deploy` to pull in dependencies
1. Compile by running `mbed compile -t GCC_ARM -m (K64F|NUCLEO_F429ZI|UBLOX_EVK_ODIN_W2)`
1. Use this [script](https://github.com/ARMmbed/mbed-cloud-client-example/blob/master/tools/combine_bootloader_with_app.py) to combine the bootloader with application `python tools/combine_bootloader_with_app.py -a {application.bin} -b {bootloader.bin} --app-offset {firmware_metadata_header_address+firmware_metadata_header_size} --header-offset {firmware_metadata_header_address} -o {combined.bin}`.
1. Flash `{combined.bin}` to device by drag and drop.

## Configurations

User **must** set in `mbed_app.json`:
1. `firmware_metadata_header_address`, Offset at which the metadata header of the active firmware is written. **Must align to flash erase boundary**
1. `firmware_metadata_header_size`, Size of the active metadata header region. The application starts at `firmware_metadata_header_address + firmware_metadata_header_size`. **Must align to vector table size boundary and flash erase boundary**
1. `update-client.application-details`, This is the same as `firmware_metadata_header_address` but needs to be configured to allow the dependency module of bootloader to pick up this configuration.

User **may** set in `mbed_app.json`:
1. `MAX_COPY_RETRIES`, The number of retries after a failed copy attempt.
1. `MAX_FIRMWARE_LOCATIONS`, The maximum number of stored firmware candidates.
1. `MAX_BOOT_RETRIES`, The number of retries after a failed forward to application.
1. `SHOW_PROGRESS_BAR`, Set to 1 to print a progress bar for various processes.

## Flash Layout
### The expected flash layout
```
    +--------------------------+
    |                          |
    |                          |
    |                          |
    |                          |     
    +--------------------------+ 
    |                          |     
    |                          |
    |                          |
    |        Active App        |     
    |                          |
    |                          |
    |                          |     firmware_metadata_header_address
    +--------------------------+ <-+              +
    |                          |     firmware_metadata_header_size 
    |Active App Metadata Header|
    |                          |
    +--------------------------+ <-+ firmware_metadata_header_address
    |                          |
    +--------------------------+
    |                          |
    |        Bootloader        |
    |                          |
    |                          |
    +--------------------------+ <-+ 0
```

### Alignment
**Flash Erase Boundary**: Flash can usually only be erased in blocks of specific sizes, this is platform specific and hence many regions need to align to this boundary.

**Vector Table Size Boundary**: The ARM architecture dictates that the Vector table of the application must be placed at an address that aligns to the next power of 2 of the size of the vector table.

## External Storage

The firmware update candidates are currently stored on an external sd card with a FAT32 file system. The expected folder structure is as follows:
```
SDRoot
  +-- firmware
        +-- header_0.bin
        +-- firmware_0.bin
        +-- header_1.bin
        +-- firmware_1.bin
        +-- ...
```
