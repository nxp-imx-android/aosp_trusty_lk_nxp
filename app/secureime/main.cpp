/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 NXP
 */

#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <lk/err_ptr.h>
#include <lk/macros.h>
#include <sys/mman.h>
#include <uapi/err.h>
#include <assert.h>

#include <secureime.h>

#define TLOG_TAG "secureime"

static int secureime_recv(handle_t chan,
                               secureime_req* req,
                               handle_t* h) {
    int rc;
    ipc_msg_info msg_info;
    uint32_t max_num_handles = h ? 1 : 0;
    struct iovec iov = {
            .iov_base = req,
            .iov_len = sizeof(*req),
    };
    struct ipc_msg ipc_msg = {
            .num_iov = 1,
            .iov = &iov,
            .num_handles = max_num_handles,
            .handles = h,
    };

    rc = get_msg(chan, &msg_info);
    if (rc != NO_ERROR) {
        TLOGE("Failed to get message (%d)\n", rc);
        return rc;
    }

    if (msg_info.len > sizeof(*req)) {
        TLOGE("Message is too long (%zd)\n", msg_info.len);
        rc = ERR_BAD_LEN;
        goto out;
    }

    if (msg_info.num_handles > max_num_handles) {
        TLOGE("Message has too many handles (%u)\n", msg_info.num_handles);
        rc = ERR_TOO_BIG;
        goto out;
    }

    rc = read_msg(chan, msg_info.id, 0, &ipc_msg);

out:
    put_msg(chan, msg_info.id);
    return rc;
}

static void secureime_on_channel_cleanup(void* _ctx) {
    struct chan_ctx* ctx = (struct chan_ctx*)_ctx;

    /* Abort operation and free all resources. */
    munmap(ctx->shm_base, ctx->shm_len);
    free(ctx);
}

static int secureime_on_connect(const struct tipc_port* port,
                      handle_t chan,
                      const struct uuid* peer,
                      void** ctx_p) {
    struct chan_ctx* ctx = (struct chan_ctx*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        TLOGE("Failed to allocate channel context\n");
        return ERR_NO_MEMORY;
    }
    ctx->shm_base = nullptr;
    ctx->shm_len  = 0;
    ctx->buffer_size = 0;

    *ctx_p = ctx;
    return NO_ERROR;
}

static keyboardView *keyboard = nullptr;
static handle_t shm_handle = INVALID_IPC_HANDLE;

static int secureime_on_message(const struct tipc_port* port,
                                handle_t chan,
                                void* _ctx) {
    int rc;
    struct secureime_req req;
    struct chan_ctx* ctx = (struct chan_ctx*)_ctx;

    assert(ctx);

    rc = secureime_recv(chan, &req, &shm_handle);
    if (rc < 0) {
        TLOGE("Failed to receive secureime request (%d)\n", rc);
        return rc;
    }

    if (rc != (int)sizeof(req)) {
        TLOGE("Receive request of unexpected size(%d)\n", rc);
        rc = ERR_BAD_LEN;
        goto out;
    }

    switch (req.cmd) {
        case SECURE_IME_CMD_INIT:
            rc = secureime_init(chan, shm_handle, &req, ctx, &keyboard);
            goto out;

        case SECURE_IME_CMD_INPUT:
            rc = secureime_handle_input(chan, &req, ctx, keyboard);
            goto out;

        case SECURE_IME_CMD_EXIT:
            rc = secureime_handle_exit(chan, &req, ctx, keyboard);
            close(shm_handle);
            goto out;

        default:
            TLOGE("cmd 0x%x: unknown command\n", req.cmd);
            rc = ERR_CMD_UNKNOWN;
            goto out;
    }
    // TODO send resp for each command

out:
    return rc;
}

static struct tipc_srv_ops ops = {
    .on_connect = secureime_on_connect,
    .on_message = secureime_on_message,
    .on_channel_cleanup = secureime_on_channel_cleanup,
};

static struct tipc_port_acl acl = {
    .flags = IPC_PORT_ALLOW_NS_CONNECT,
};

static struct tipc_port port = {
    .name = SECUREIME_PORT_NAME,
    .msg_max_size = SECUREIME_MAX_MSG_SIZE,
    .msg_queue_len = 1,
    .acl = &acl,
};

int main(void) {
    int rc = 0;
    struct tipc_hset *hset;
    TLOGE("secureime init.\n");

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("failed to create hset\n");
        return PTR_ERR(hset);
    }

    rc =  tipc_add_service(hset, &port, 1, 2, &ops);
    if (rc != NO_ERROR) {
        TLOGE("failed to add secureime service:%d\n", rc);
        return rc;
    }

    return tipc_run_event_loop(hset);
}
