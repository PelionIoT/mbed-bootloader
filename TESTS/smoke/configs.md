# Target configs

Following table is parsed automatically by build scripts, so follow the format EXACTLY. Do not add spaces.

|TARGET|BOOTLOADER_BIN|HEADER_OFFSET|APP_OFFSET|UPDATE_HEADER_OFFSET|UPDATE_APP_OFFSET|
|------|--------------|-------------|---------|--------------------|------------------|
|DISCO_L475VG_IOT01A|../../BUILD/mbed_app/DISCO_L475VG_IOT01A/GCC_ARM/mbed-bootloader.bin|0x8000|0x8400|0x80000|0x80070|
|K64F|../../BUILD/mbed_app/K64F/GCC_ARM/mbed-bootloader.bin|0x8000|0x8400|0x80000|0x80070|
|NRF52840_DK|../../BUILD/mbed_app/NRF52840_DK/GCC_ARM/mbed-bootloader.hex|0x8000|0x8400|0x80000|0x80070|
|NUCLEO_F303RE|../../BUILD/mbed_app/NUCLEO_F303RE/GCC_ARM/mbed-bootloader.bin|0x8000|0x8400|0x40000|0x40070|
|NUCLEO_F411RE|../../BUILD/mbed_app/NUCLEO_F411RE/GCC_ARM/mbed-bootloader.bin|0x8000|0x8400|0x40000|0x40070|
|NUCLEO_F429ZI|../../BUILD/mbed_app/NUCLEO_F429ZI/GCC_ARM/mbed-bootloader.bin|0x8000|0x8400|0x100000|0x100070|
|DISCO_F769NI|../../BUILD/mbed_app/DISCO_F769NI/GCC_ARM/mbed-bootloader.bin|0x40000|0x40400|0x100000|0x100070|
|GR_MANGO|../../BUILD/GR_MANGO/GCC_ARM/mbed-bootloader.bin|0x10000|0x10400|0x800000|0x800070|


## Finding the values

Most values could be found from the `mbed_app.json` used for building the binary.

* **BOOTLOADER_BIN** should be the relative path to booatloder binary (.hex or .bin)
* **HEADER_OFFSET**  is `update-client.application-details` from `mbed_app.json`
* **APP_OFFSET**     is `mbed-bootloader.application-start-address`
* **UPDATE_HEADER_OFFSET** is `update-client.storage-address`
* **UPDATE_APP_OFFSET**    is `UPDATE_HEADER_OFFSET + ARM_UC_INTERNAL_HEADER_SIZE_V2`

Usually you need to calculate these values from `mbed_config.h`, sometimes these are easy to find from compilation output.

```
Building project mbed-bootloader (K64F, GCC_ARM)
Scan: mbed-bootloader
Using ROM regions application, post_application in this build.
  Region application: size 0x8000, offset 0x0
  Region post_application: size 0xf8000, offset 0x8000
```

Offset value on the line `Region post_application` is actually same as **HEADER_OFFSET**.

Now we can also calculate the start address, as it is defined as follows:

```
"mbed-bootloader.application-start-address": "(MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS + MBED_BOOTLOADER_ACTIVE_HEADER_REGION_SIZE)",
```

Where `MBED_BOOTLOADER_ACTIVE_HEADER_REGION_SIZE=1024` is defined in the same `mbed_app.json`.
Therefore **APP_OFFSET** would be `0x8000 + 1024 = 0x8400`

For update image location, following is defined in `mbed_app.json` and visible in the `mbed_config.h`

```
#define MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS  (MBED_ROM_START + MBED_BOOTLOADER_FLASH_BANK_SIZE)
#define MBED_BOOTLOADER_FLASH_BANK_SIZE MBED_ROM_SIZE/2
```

`MBED_ROM_START` was visible in the compilation output as `Region application ... offset`, which is now `0x0`.

`MBED_ROM_SIZE` must be calulated by appeding both region sizes from compilation output `0x8000 + 0xf8000 = 0x100000 (1 MB)`
Then `MBED_BOOTLOADER_FLASH_BANK_SIZE = MBED_ROM_SIZE/2 = 0x100000 = 0x80000`

And now we can calculate the storage address:
`MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS = MBED_ROM_START + MBED_BOOTLOADER_FLASH_BANK_SIZE = 0x0 + 0x80000 = 0x80000`

Next, we can calculate the application offset. Current `ARM_UC_INTERNAL_HEADER_SIZE_V2` is 112 bytes.
So `0x80000 + 112 = 0x80070`, therefore `UPDATE_APP_OFFSET` is `0x80070`

**NOTE:** All offset values are based on ROM start, not absolute addresses. If device has rom size starting from other than 0, that value must be subtracted from calculated offsets. See F429ZI for example.
