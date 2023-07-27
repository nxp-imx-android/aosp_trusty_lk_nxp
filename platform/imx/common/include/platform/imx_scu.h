/*
 * Copyright 2023 NXP
 *
 */
#ifndef _IMX_SCU_H_
#define _IMX_SCU_H_
#define SYSCALL_PLATFORM_FD_SCU 0x9

struct scu_alloc_part_msg {
    uint8_t part;
};

#define SCU_ALLOC_PART         0x00000001
#define SCU_MEM_PERMISSION     0x00000002
#define SCU_POWER_ON_VPU       0x00000003

#endif

