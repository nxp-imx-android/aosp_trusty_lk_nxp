/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#define TLOG_TAG "widevine_l3"

#include <assert.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include <imx-regs.h>
#include <lib/hwsecure/hwsecure.h>

#define WIDEVINE_L3_PORT "com.android.trusty.widevine"

static struct tipc_port_acl widevine_l3_port_acl = {
        .flags = IPC_PORT_ALLOW_NS_CONNECT,
};

static struct tipc_port widevine_l3_port = {
        .name = WIDEVINE_L3_PORT,
        .msg_max_size = 1024,
        .msg_queue_len = 1,
        .acl = &widevine_l3_port_acl,
};

static int on_message(const struct tipc_port* port, handle_t chan, void* ctx) {
    return 0;
}

static struct tipc_srv_ops widevine_l3_ops = {
        .on_message = on_message,
};

int main(void) {
    int rc;
    struct tipc_hset* hset;

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        return PTR_ERR(hset);
    }

    rc = tipc_add_service(hset, &widevine_l3_port, 1, 0, &widevine_l3_ops);
    if (rc != NO_ERROR) {
        return rc;
    }

    /* config memory permission */
#if defined(MACH_IMX8QM)
    rc = set_widevine_secure_pipeline();
    if (rc < 0) {
        TLOGE("widevine l3 app failed to set secure pipeline ret : %d\n", rc);
        return rc;
    } else {
        TLOGD("widevine l3 app set secure pipeline successfully\n");
    }
#endif

    return tipc_run_event_loop(hset);
}
