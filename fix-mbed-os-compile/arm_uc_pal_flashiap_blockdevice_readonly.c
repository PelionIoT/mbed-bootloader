#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_implementation.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_implementation.h"

#if defined(ARM_UC_USE_PAL_BLOCKDEVICE) && (ARM_UC_USE_PAL_BLOCKDEVICE==1)

extern arm_uc_error_t ARM_UCP_FashIAP_BlockDevice_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback);

ARM_UC_PAAL_UPDATE ARM_UCP_FLASHIAP_BLOCKDEVICE_READ_ONLY =
{
    .Initialize                 = ARM_UCP_FashIAP_BlockDevice_Initialize,
    .GetCapabilities            = 0,
    .GetMaxID                   = 0,
    .Prepare                    = 0,
    .Write                      = 0,
    .Finalize                   = 0,
    .Read                       = ARM_UC_PAL_BlockDevice_Read,
    .Activate                   = 0,
    .GetActiveFirmwareDetails   = ARM_UC_PAL_FlashIAP_GetActiveDetails,
    .GetFirmwareDetails         = ARM_UC_PAL_BlockDevice_GetFirmwareDetails,
    .GetInstallerDetails        = 0
};

#endif /* ARM_UC_USE_PAL_BLOCKDEVICE */
