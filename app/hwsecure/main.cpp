/*
 * Copyright 2023 NXP
 *
 */

#include <lib/tipc/tipc.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <lk/err_ptr.h>
#include "hwsecure_srv.h"
#include "hwsecure.h"
#include "imx-regs.h"

#define TLOG_TAG "hwsecure"

static handle_t hwsecure_handle = INVALID_IPC_HANDLE;

int main(void) {
    int rc = 0;
    struct tipc_hset *hset;
    TLOGE("hwsecure init.\n");

#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM) || defined (MACH_IMX8MQ)
    if(init_csu() || init_rdc()) {
        TLOGE("hardware error!\n");
        return -1;
    }
#endif

    hset = tipc_hset_create();

    if (IS_ERR(hset)) {
        TLOGE("failed to create hset\n");
        return PTR_ERR(hset);
    }

    rc = add_hwsecure_service(hset, &hwsecure_handle);

    if (rc != NO_ERROR) {
        TLOGE("failed to add secure:%d\n", rc);
        return rc;
    }

    return tipc_run_event_loop(hset);
}
