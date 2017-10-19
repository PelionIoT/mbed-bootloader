//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2016 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#ifndef __BOOTLOADER_PLATFORM_H__
#define __BOOTLOADER_PLATFORM_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool        existsErrorMessageLeadingToReboot(void);
const char *errorMessageLeadingToReboot(void);
void        forwardControlToApplication(void);

#ifdef __cplusplus
}
#endif

#endif /*#ifndef __BOOTLOADER_PLATFORM_H__*/
