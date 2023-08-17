/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _IMX_SCU_H_
#define _IMX_SCU_H_
#define SYSCALL_PLATFORM_FD_SCU 0x9

struct scu_alloc_part_msg {
    uint8_t part;
};

#define SCU_POWER_ON_VPU       0x00000003

#endif

