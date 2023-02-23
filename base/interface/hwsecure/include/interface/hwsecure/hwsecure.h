/*
 * Copyright 2023 NXP
 *
 */

#pragma once

#include <stdint.h>

#define HWSECURE_PORT_NAME "com.nxp.trusty.hwsecure"

#define HWSECURE_MAX_MSG_SIZE 64

enum hwsecure_cmd {
    HWSECURE_RESP_BIT = 1,
    HWSECURE_REQ_SHIFT = 1,

    HWSECURE_TEST_CMD = (1 << HWSECURE_REQ_SHIFT),
    HWSECURE_LCDIF_SECURE_ACCESS = (2 << HWSECURE_REQ_SHIFT),
    HWSECURE_LCDIF_NON_SECURE_ACCESS = (3 << HWSECURE_REQ_SHIFT),
    HWSECURE_WV_G2D_SECURE = (6 << HWSECURE_REQ_SHIFT),
    HWSECURE_WV_G2D_NON_SECURE = (7 << HWSECURE_REQ_SHIFT),
    HWSECURE_WV_GET_G2D_SECURE_MODE = (8 << HWSECURE_REQ_SHIFT),
    HWSECURE_DCSS_SECURE_ACCESS = (9 << HWSECURE_REQ_SHIFT),
    HWSECURE_DCSS_NON_SECURE_ACCESS = (10 << HWSECURE_REQ_SHIFT),
    HWSECURE_DCNANO_SECURE_ACCESS = (11 << HWSECURE_REQ_SHIFT),
    HWSECURE_DCNANO_NON_SECURE_ACCESS = (12 << HWSECURE_REQ_SHIFT),
    HWSECURE_SET_RDC_MEM_REGION = (13 << HWSECURE_REQ_SHIFT),
    HWSECURE_IME_SECURE_ACCESS = (14 << HWSECURE_REQ_SHIFT),
    HWSECURE_IME_NON_SECURE_ACCESS = (15 << HWSECURE_REQ_SHIFT),
    HWSECURE_IME_GET_SECURE_MODE = (16 << HWSECURE_REQ_SHIFT),
};

struct hwsecure_req {
    uint32_t cmd;
};

struct hwsecure_resp {
    uint32_t cmd;
    int32_t status;
};

enum g2d_secure_mode {
    SECURE = 1,
    NON_SECURE = 2
};
