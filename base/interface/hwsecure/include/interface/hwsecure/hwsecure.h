#pragma once

#include <stdint.h>

#define HWSECURE_PORT_NAME "com.nxp.trusty.hwsecure"

#define HWSECURE_MAX_MSG_SIZE 64

enum hwsecure_cmd {
    HWSECURE_TEST_CMD = 1,
    HWSECURE_LCDIF_SECURE_ACCESS = 2,
    HWSECURE_LCDIF_NON_SECURE_ACCESS = 3,
    HWSECURE_WV_VPU_SECURE = 4,
    HWSECURE_WV_VPU_NON_SECURE = 5,
    HWSECURE_WV_G2D_SECURE = 6,
    HWSECURE_WV_G2D_NON_SECURE = 7,
    HWSECURE_WV_GET_G2D_SECURE_MODE = 8
};

struct hwsecure_req {
    uint32_t cmd;
};

enum g2d_secure_mode {
    SECURE = 1,
    NON_SECURE = 2
};
