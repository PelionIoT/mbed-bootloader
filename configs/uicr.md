# Nordic Semiconductor Bootloader support

If SoftDevice is used the start address of the bootloader needs to be passed for the device by using User Information Configuration Registers (UICR). This can be accomplished by combining the produced bootloader binary with an uicr.hex file. If SoftDevice is not used this setting doesn't have any effect. For futher instructions please see the [documentation](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fsds_s132%2FSDS%2Fs1xx%2Fmbr_bootloader%2Fbootloader.html&cp=3_4_2_0_11_1).
