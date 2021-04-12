#pragma once

#include <stdint.h>

#define HWSECURE_PORT_NAME "com.nxp.trusty.hwsecure"

#define HWSECURE_MAX_MSG_SIZE 64

enum hwsecure_cmd {
    HWSECURE_TEST_CMD = 1,
    HWSECURE_LCDIF_SECURE_ACCESS = 2,
    HWSECURE_LCDIF_NON_SECURE_ACCESS = 3,
    HWSECURE_WV_VPU_SECURE = 4,
    HWSECURE_WV_VPU_NON_SECURE = 5

};

struct hwsecure_req {
    uint32_t cmd;
};
