/*
 * Copyright 2023 NXP
 *
 */

#ifndef _CSU_COMMON_H_
#define _CSU_COMMON_H_

#define SYSCALL_PLATFORM_FD_CSU 0x8 //Maxium 0xA

#define CSU_OK 0
#define CSU_ERR 1

#define CSU_IOCMD_STATUS        0x00000001
#define CSU_IOCMD_CFG_SA        0x00000002
#define CSU_IOCMD_CFG_CSL       0x00000003
#define CSU_IOCMD_SECURE_DISP   0x00000004

struct csu_cfg_sa_msg {
    uint32_t id;
    uint32_t enable;
};

struct csu_cfg_csl_msg {
    uint32_t id;
    uint32_t val;
};

struct csu_cfg_secure_disp_msg {
    uint32_t enable;
    uint32_t paddr;
};

#endif
