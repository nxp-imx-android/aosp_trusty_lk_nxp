#include <interface/hwsecure/hwsecure.h>
#include <lib/tipc/tipc.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <lk/err_ptr.h>
#include <lib/tipc/tipc_srv.h>
#include "hwsecure_srv.h"
#include "hwsecure.h"

#define TLOG_TAG "hwsecure_srv"

static hwservice_context ctx;

static struct tipc_port_acl acl = {
        .flags = IPC_PORT_ALLOW_TA_CONNECT,
        // TODO: uuid_num and uuids need set later
};

static struct tipc_port port = {
    .name = HWSECURE_PORT_NAME,
    .msg_max_size = HWSECURE_MAX_MSG_SIZE,
    .msg_queue_len = 1,
    .acl = &acl,
    .priv = &ctx,
};

static int hwsecure_on_connect(const struct tipc_port* port,
                                handle_t chan,
                                const struct uuid* peer,
                                void** ctx_p) {

    TLOGE("hwsecure_on_connect\n");

    return NO_ERROR;
}

static void hwsecure_on_disconnect(const struct tipc_port* port,
                                    handle_t chan,
                                    void* ctx) {

    TLOGE("hwsecure_on_disconnect\n");
}

static int hwsecure_on_message(const struct tipc_port* port,
                                handle_t chan,
                                void* _ctx) {
    int rc;
    struct hwsecure_req req;
    rc = tipc_recv1(chan, sizeof(req), &req, sizeof(req));

    if (rc < 0) {
        TLOGE("failed to recv req \n");
    }

    switch(req.cmd) {
        case HWSECURE_LCDIF_SECURE_ACCESS:
        case HWSECURE_LCDIF_NON_SECURE_ACCESS:
            set_lcdif_secure(req.cmd);
            break;
        default:
            return ERR_INVALID_ARGS;
    }
    return NO_ERROR;
}

int add_hwsecure_service(struct tipc_hset *hset, handle_t *chan) {
    if (!hset || !chan)
        return ERR_INVALID_ARGS;

    ctx.chan = chan;

    static struct tipc_srv_ops ops = {
        .on_connect = hwsecure_on_connect,
        .on_message = hwsecure_on_message,
        .on_disconnect = hwsecure_on_disconnect,
    };

    return tipc_add_service(hset, &port, 1, 2, &ops);
}
