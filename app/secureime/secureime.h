/*
 * Copyright 2022 NXP
 */

#ifndef __SECURE_IME_H__
#define __SECURE_IME_H__

#include <stdint.h>
#include <stddef.h>
#include <trusty_ipc.h>
#include "keyboard_view.h"

#define SECUREIME_PORT_NAME "com.android.trusty.secureime"
#define SECUREIME_MAX_MSG_SIZE 1024

enum secureime_command: uint32_t {
    SECURE_IME_REQ_SHIFT = 1,
    SECURE_IME_RESP_BIT = 1,

    SECURE_IME_CMD_INIT   = (0 << SECURE_IME_REQ_SHIFT),
    SECURE_IME_CMD_INPUT  = (1 << SECURE_IME_REQ_SHIFT),
    SECURE_IME_CMD_EXIT   = (2 << SECURE_IME_REQ_SHIFT),
};

struct chan_ctx {
    void* shm_base;
    size_t shm_len; // aligned shared memory size
    size_t buffer_size; // actual shared memory size
};


struct secureime_req {
    int cmd;
    int buffer_size;
    int width;
    int height;
    int stride;
    int x;
    int y;
};

struct secureime_resp {
    uint32_t cmd;
    int key;
    int result;
};

int secureime_handle_input(handle_t chan,
                       struct secureime_req *req,
                       struct chan_ctx* ctx,
                       keyboardView *keyboard);

int secureime_init(handle_t chan,
                       handle_t shm_handle,
                       struct secureime_req *req,
                       struct chan_ctx* ctx,
                       keyboardView **keyboard);

int secureime_handle_exit(handle_t chan,
                       struct secureime_req *req,
                       struct chan_ctx* ctx,
                       keyboardView *keyboard);

#endif /* __SECURE_IME_H__ */
