//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include "pal.h"

#ifndef MAX_COPY_RETRIES
#define MAX_COPY_RETRIES 1
#endif

extern uint64_t* heapVersion;
extern uint8_t* bootCounter;

void palEventHandlerStub(uint32_t event);

/**
 * Find suitable update candidate and copy firmware into active region
 * @return true if the active firmware region is valid.
 */
bool upgradeApplicationFromStorage(void);
