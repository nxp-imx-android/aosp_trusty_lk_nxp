/*
 * Copyright 2022 NXP
 */

#include <secureime.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <lk/macros.h>
#include <sys/mman.h>
#include <trusty_log.h>
#include <uapi/err.h>
#include <uapi/mm.h>
#include <trusty/sys/mman.h>
#include <trusty/time.h>

#include "keyboard_view.h"

#define TLOG_TAG "secureime"
#define PAGE_SIZE 4096

static inline bool is_inited(struct chan_ctx* ctx) {
    return ctx->shm_base;
}

int secureime_handle_input(handle_t chan,
                       struct secureime_req *req,
                       struct chan_ctx* ctx,
                       keyboardView *keyboard) {
    int x, y, key, rc;
    struct secureime_resp resp;

    if (!is_inited(ctx) || !keyboard) {
        TLOGE("display buffer is not initialized!\n");
        return NO_ERROR;
    }

    x = req->x;
    y = req->y;

    key = keyboard->getKeyboardText(x, y);

    resp.cmd = SECURE_IME_CMD_INPUT | SECURE_IME_RESP_BIT;
    resp.key = key;
    resp.result = NO_ERROR;
    rc = tipc_send1(chan, &resp, sizeof(resp));
    if (rc != (int)sizeof(resp)) {
        TLOGE("Failed to send response (%d)\n", rc);
        if (rc >= 0) {
            rc = ERR_BAD_LEN;
        }
        return rc;
    }

    return NO_ERROR;
}

int secureime_init(handle_t chan,
                       handle_t shm_handle,
                       struct secureime_req *req,
                       struct chan_ctx* ctx,
                       keyboardView **keyboard) {
    int rc = NO_ERROR;
    struct secureime_resp resp;
    void* shm_base = NULL;

    if (is_inited(ctx)) {
        TLOGE("display buffer is already initialized.\n");
        rc = ERR_BAD_STATE;
        goto exit;
    }

    shm_base = mmap(0, align(req->buffer_size, PAGE_SIZE),
                             PROT_READ | PROT_WRITE, 0, shm_handle, 0);
    if (shm_base == MAP_FAILED) {
        TLOGE("Failed to mmap() handle\n");
        rc = ERR_BAD_HANDLE;
        goto exit;
    }

    ctx->shm_base = shm_base;
    ctx->shm_len = align(req->buffer_size, PAGE_SIZE);
    ctx->buffer_size = req->buffer_size;

    *keyboard = new keyboardView((uint8_t *)shm_base, req->buffer_size, req->width, req->height);
    rc = (*keyboard)->drawKeyboard();
    if (rc != NO_ERROR) {
        TLOGE("Failed to draw keyboard!\n");
        goto unmap;
    }

unmap:
    if (rc != NO_ERROR)
        munmap(shm_base, align(req->buffer_size, PAGE_SIZE));

exit:
    /* send response */
    resp.cmd = SECURE_IME_CMD_INIT | SECURE_IME_RESP_BIT;
    resp.result = rc;
    rc = tipc_send1(chan, &resp, sizeof(resp));
    if (rc != (int)sizeof(resp)) {
        TLOGE("Failed to send response (%d)\n", rc);
        if (rc >= 0) {
            rc = ERR_BAD_LEN;
        }
    }

    return rc;
}

int secureime_handle_exit(handle_t chan,
                       struct secureime_req *req,
                       struct chan_ctx* ctx,
                       keyboardView *keyboard) {
    int rc = NO_ERROR;
    delete keyboard;
    keyboard = nullptr;

    /* reset the surface buffer */
    uint32_t *pixel = (uint32_t *)(ctx->shm_base);
    for(uint32_t i = 0; i < ctx->buffer_size / 4; i++)
        pixel[i] = 0;

    munmap(ctx->shm_base, ctx->shm_len);
    ctx->shm_base = nullptr;

    return rc;
}
