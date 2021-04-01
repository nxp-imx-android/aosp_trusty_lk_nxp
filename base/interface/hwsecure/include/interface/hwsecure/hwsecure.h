#pragma once

#include <stdint.h>

#define HWSECURE_PORT_NAME "com.nxp.trusty.hwsecure"

#define HWSECURE_MAX_MSG_SIZE 64

enum hwsecure_cmd {
    HWSECURE_LCDIF_SECURE_ACCESS = 1,
    HWSECURE_LCDIF_NON_SECURE_ACCESS = 2,
    HWSECURE_TEST_CMD = 3,
};

struct hwsecure_req {
    uint32_t cmd;
};
