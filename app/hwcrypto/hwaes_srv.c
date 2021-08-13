/*
 * Copyright 2021 NXP
 */

#include <assert.h>
#include <lk/compiler.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include "common.h"
#include <lib/hwaes_server/hwaes_server.h>

#define TLOG_TAG "hwaes_srv"

#define HWAES_MAX_PAYLOAD_SIZE 2048

struct hwaes_chan_ctx {
    tipc_event_handler_t evt_handler;
    handle_t chan;
    uuid_t uuid;
};

static void hwaes_port_handler(const uevent_t* ev, void* priv);
static void hwaes_chan_handler(const uevent_t* ev, void* priv);

static tipc_event_handler_t hwaes_port_evt_handler = {
        .proc = hwaes_port_handler,
};

/*
 * Close specified hwaes context
 */
static void hwaes_ctx_close(struct hwaes_chan_ctx* ctx) {
    close(ctx->chan);
    free(ctx);
}

/*
 *  HWAES service channel event handler
 */
static void hwaes_chan_handler(const uevent_t* ev, void* priv) {
    struct hwaes_chan_ctx* ctx = priv;

    assert(ctx);
    assert(ev->handle == ctx->chan);

    tipc_handle_chan_errors(ev);

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        hwaes_ctx_close(ctx);
        return;
    }

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        int rc = hwaes_handle_message(ctx->chan);
        if (rc < 0) {
            /* report an error and close channel */
            TLOGE("failed (%d) to handle event on channel %d\n", rc,
                  ev->handle);
            hwaes_ctx_close(ctx);
        }
    }
}

/*
 * HWAES service port event handler
 */
static void hwaes_port_handler(const uevent_t* ev, void* priv) {
    uuid_t peer_uuid;

    tipc_handle_port_errors(ev);

    if (ev->event & IPC_HANDLE_POLL_READY) {
        /* incoming connection: accept it */
        int rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGE("failed (%d) to accept on port %d\n", rc, ev->handle);
            return;
        }

        handle_t chan = (handle_t)rc;
        struct hwaes_chan_ctx* ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            TLOGE("failed (%d) to allocate context on chan %d\n", rc, chan);
            close(chan);
            return;
        }

        /* init channel state */
        ctx->evt_handler.priv = ctx;
        ctx->evt_handler.proc = hwaes_chan_handler;
        ctx->chan = chan;
        ctx->uuid = peer_uuid;

        rc = set_cookie(chan, &ctx->evt_handler);
        if (rc < 0) {
            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan);
            hwaes_ctx_close(ctx);
            return;
        }
    }
}

/*
 *  Initialize HWAES service
 */
int hwaes_start_service(void) {
    int rc;
    handle_t port;

    TLOGD("Start HWAES service\n");

    /* Initialize service */
    rc = port_create(HWAES_PORT, 1, HWAES_MAX_PAYLOAD_SIZE,
                     IPC_PORT_ALLOW_TA_CONNECT);
    if (rc < 0) {
        TLOGE("Failed (%d) to create port %s\n", rc, HWAES_PORT);
        return rc;
    }

    port = (handle_t)rc;
    rc = set_cookie(port, &hwaes_port_evt_handler);
    if (rc) {
        TLOGE("failed (%d) to set_cookie on port %d\n", rc, port);
        close(port);
        return rc;
    }

    return NO_ERROR;
}
