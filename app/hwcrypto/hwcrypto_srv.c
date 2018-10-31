/*
 * Copyright (C) 2016-2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2018 NXP
 */

#include <assert.h>
#include <lk/compiler.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_ipc.h>
#include <uapi/err.h>

#include <interface/hwcrypto/hwcrypto.h>

#include "common.h"
#include "hwcrypto_srv_priv.h"
#include "uuids.h"

#define TLOG_LVL TLOG_LVL_DEFAULT
#define TLOG_TAG "hwcrypto_srv"
#include "tlog.h"

#define HWCRYPTO_MAX_PAYLOAD_SIZE 2048

/**
 * hwcrypto_hash_msg - Serial header for communicating with hwcrypto server
 * @in_addr:  start address of the input buf.
 * @in_len:   size of the input buf.
 * @out_addr: start addrss of the output buf.
 * @out_len:  size of the output buf.
 * @algo:     hash algorithm expect to use.
 */
typedef struct hwcrypto_hash_msg {
    uint32_t in_addr;
    uint32_t in_len;
    uint32_t out_addr;
    uint32_t out_len;
    enum hash_algo algo;
} hwcrypto_hash_msg;

struct hwcrypto_chan_ctx {
    tipc_event_handler_t evt_handler;
    handle_t chan;
    uuid_t uuid;
};

static void hwcrypto_port_handler(const uevent_t* ev, void* priv);
static void hwcrypto_chan_handler(const uevent_t* ev, void* priv);

static tipc_event_handler_t hwcrypto_port_evt_handler = {
        .proc = hwcrypto_port_handler,
};

/* Make sure that key_data and reg_data buffers are not crossing page boundary
 * so it is safe to pass them to DMA. An extra byte for req_data buf is used to
 * zero terminate string so it is OK to have it on separate page as it will
 * never be accesed by DMA engine.
 */
static uint8_t req_data[HWCRYPTO_MAX_PAYLOAD_SIZE + 1]
        __attribute__((aligned(HWCRYPTO_MAX_PAYLOAD_SIZE)));

/*
 * Close specified hwcrypto context
 */
static void hwcrypto_ctx_close(struct hwcrypto_chan_ctx* ctx) {
    close(ctx->chan);
    free(ctx);
}

/*
 * Send response message
 */
static int hwcrypto_send_rsp(struct hwcrypto_chan_ctx* ctx,
                          struct hwcrypto_msg* rsp_hdr,
                          uint8_t* rsp_data,
                          size_t rsp_data_len) {
    rsp_hdr->cmd |= HWCRYPTO_RESP_BIT;
    return tipc_send_two_segments(ctx->chan, rsp_hdr, sizeof(*rsp_hdr),
                                  rsp_data, rsp_data_len);
}

/*
 * Handle get hash command
 */
static int hwcrypto_hash_process(struct hwcrypto_chan_ctx* ctx,
                                        struct hwcrypto_msg* hdr,
                                        uint8_t *req_data,
					size_t req_data_len)
{
    assert(hdr);
    assert(req_data);

    /* sanity check the req length */
    if (req_data_len < sizeof(hwcrypto_hash_msg)) {
	    hdr->status = HWCRYPTO_ERROR_INVALID;
	    goto fail;
    }

    hwcrypto_hash_msg *msg = (hwcrypto_hash_msg *)req_data;
    if ((msg->in_addr == 0) || (msg->out_addr == 0)) {
        hdr->status = HWCRYPTO_ERROR_INVALID;
	goto fail;
    }

    /* canculate hash with caam */
    hdr->status = calculate_hash(msg->in_addr, msg->in_len, msg->out_addr, msg->algo);

fail:
    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

/*
 * Handle encapsulate blob command
 */
static int hwcrypto_encap_blob(struct hwcrypto_chan_ctx* ctx,
                               struct hwcrypto_msg* hdr,
                               uint8_t *req_data,
                               size_t req_data_len)
{
    assert(hdr);
    assert(req_data);

    /* sanity check the req length */
    if (req_data_len < sizeof(hwcrypto_blob_msg)) {
	    hdr->status = HWCRYPTO_ERROR_INVALID;
	    goto fail;
    }

    hwcrypto_blob_msg *msg = (hwcrypto_blob_msg *)req_data;
    if ((msg->plain_pa == 0) || (msg->blob_pa == 0)) {
        hdr->status = HWCRYPTO_ERROR_INVALID;
	goto fail;
    }

    /* use caam to encapsulate the text located in msg->plain_pa with
     * length 'size', generated blob will be stored to msg->blob_pa.
     */
    hdr->status = caam_encap_blob(msg->plain_pa,
                                  msg->plain_size, msg->blob_pa);

fail:
    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

/*
 *  Read and queue HWCRYPTO request message
 */
static int hwcrypto_chan_handle_msg(struct hwcrypto_chan_ctx* ctx) {
    int rc;
    size_t req_data_len;
    struct hwcrypto_msg hdr;

    rc = tipc_recv_two_segments(ctx->chan, &hdr, sizeof(hdr), req_data,
                                sizeof(req_data) - 1);
    if (rc < 0) {
        TLOGE("failed (%d) to recv msg from chan %d\n", rc, ctx->chan);
        return rc;
    }

    /* calculate payload length */
    req_data_len = (size_t)rc - sizeof(hdr);

    /* handle it */
    switch (hdr.cmd) {
    case HWCRYPTO_HASH:
	rc = hwcrypto_hash_process(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_ENCAP_BLOB:
        rc = hwcrypto_encap_blob(ctx, &hdr, req_data, req_data_len);
        break;

    default:
        TLOGE("Unsupported request: %d\n", (int)hdr.cmd);
        hdr.status = HWCRYPTO_ERROR_INVALID;
        rc = hwcrypto_send_rsp(ctx, &hdr, NULL, 0);
    }

    return rc;
}

/*
 *  HWCRYPTO service channel event handler
 */
static void hwcrypto_chan_handler(const uevent_t* ev, void* priv) {
    struct hwcrypto_chan_ctx* ctx = priv;

    assert(ctx);
    assert(ev->handle == ctx->chan);

    tipc_handle_chan_errors(ev);

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        hwcrypto_ctx_close(ctx);
        return;
    }

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        int rc = hwcrypto_chan_handle_msg(ctx);
        if (rc < 0) {
            /* report an error and close channel */
            TLOGE("failed (%d) to handle event on channel %d\n", rc,
                  ev->handle);
            hwcrypto_ctx_close(ctx);
        }
    }
}

/*
 * HWCRYPTO service port event handler
 */
static void hwcrypto_port_handler(const uevent_t* ev, void* priv) {
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
        struct hwcrypto_chan_ctx* ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            TLOGE("failed (%d) to allocate context on chan %d\n", rc, chan);
            close(chan);
            return;
        }

        /* init channel state */
        ctx->evt_handler.priv = ctx;
        ctx->evt_handler.proc = hwcrypto_chan_handler;
        ctx->chan = chan;
        ctx->uuid = peer_uuid;

        rc = set_cookie(chan, &ctx->evt_handler);
        if (rc < 0) {
            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan);
            hwcrypto_ctx_close(ctx);
            return;
        }
    }
}

/*
 *  Initialize HWCRYPTO service
 */
int hwcrypto_start_service(void) {
    int rc;
    handle_t port;

    TLOGI("Start HWCRYPTO service\n");

    /* Initialize service */
    rc = port_create(HWCRYPTO_PORT, 1, HWCRYPTO_MAX_PAYLOAD_SIZE,
                     IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT);
    if (rc < 0) {
        TLOGE("Failed (%d) to create port %s\n", rc, HWCRYPTO_PORT);
        return rc;
    }

    port = (handle_t)rc;
    rc = set_cookie(port, &hwcrypto_port_evt_handler);
    if (rc) {
        TLOGE("failed (%d) to set_cookie on port %d\n", rc, port);
        close(port);
        return rc;
    }

    return NO_ERROR;
}
