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
 */

#include <assert.h>
#include <lk/compiler.h>
#include <lk/list.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <trusty_ipc.h>
#include <uapi/err.h>

#include <interface/hwkey/hwkey.h>
#include <nxp_hwcrypto_uuid_consts.h>

#include "common.h"
#include "hwkey_srv_priv.h"
#include "hwrng_srv_priv.h"
#include <openssl/mem.h>

#define TLOG_TAG "hwkey_srv"
#include <trusty_log.h>

#define HWKEY_MAX_PAYLOAD_SIZE 2048

struct hwkey_chan_ctx {
    tipc_event_handler_t evt_handler;
    handle_t chan;
    uuid_t uuid;
};

/**
 * An opaque key access token.
 *
 * Clients can retrieve an opaque access token as a handle to a key they are
 * allowed to use but not read directly. This handle can then be passed to other
 * crypto services which can use the token to retrieve the actual key from
 * hwkey.
 */
typedef char access_token_t[HWKEY_OPAQUE_HANDLE_SIZE];

struct opaque_handle_node {
    const struct hwkey_keyslot* key_slot;
    struct hwkey_chan_ctx* owner;
    access_token_t token;
    struct list_node node;
};

/*
 * Global list of currently valid opaque handles. Each client may only have a
 * single entry in this list for a given key slot, and this entry will be
 * cleaned up when the connection it was created for is closed.
 */
static struct list_node opaque_handles = LIST_INITIAL_VALUE(opaque_handles);

static void hwkey_port_handler(const uevent_t* ev, void* priv);
static void hwkey_chan_handler(const uevent_t* ev, void* priv);

static tipc_event_handler_t hwkey_port_evt_handler = {
        .proc = hwkey_port_handler,
};

/* Make sure that key_data and reg_data buffers are not crossing page boundary
 * so it is safe to pass them to DMA. An extra byte for req_data buf is used to
 * zero terminate string so it is OK to have it on separate page as it will
 * never be accesed by DMA engine.
 */
static uint8_t key_data[HWKEY_MAX_PAYLOAD_SIZE]
        __attribute__((aligned(HWKEY_MAX_PAYLOAD_SIZE)));
static uint8_t req_data[HWKEY_MAX_PAYLOAD_SIZE + 1]
        __attribute__((aligned(HWKEY_MAX_PAYLOAD_SIZE)));

static unsigned int key_slot_cnt;
static const struct hwkey_keyslot* key_slots;

static bool is_opaque_handle(const struct hwkey_keyslot* key_slot) {
    assert(key_slot);
    return key_slot->handler == get_key_handle;
}

static void delete_opaque_handle(struct opaque_handle_node* node) {
    assert(node);

    /* Zero out the access token just in case the memory is reused */
    memset(node->token, 0, HWKEY_OPAQUE_HANDLE_SIZE);

    list_delete(&node->node);
    free(node);
}

#if WITH_HWCRYPTO_UNITTEST
/*
 *  Support for hwcrypto unittest keys should be only enabled
 *  to test hwcrypto related APIs
 */

/* UUID of HWCRYPTO_UNITTEST application */
static const uuid_t hwcrypto_unittest_uuid = HWCRYPTO_UNITTEST_APP_UUID;

static uint8_t _unittest_key32[32] = "unittestkeyslotunittestkeyslotun";
static uint32_t get_unittest_key32(const struct hwkey_keyslot* slot,
                                   uint8_t* kbuf,
                                   size_t kbuf_len,
                                   size_t* klen) {
    assert(kbuf);
    assert(klen);
    assert(kbuf_len >= sizeof(_unittest_key32));

    /* just return predefined key */
    memcpy(kbuf, _unittest_key32, sizeof(_unittest_key32));
    *klen = sizeof(_unittest_key32);

    return HWKEY_NO_ERROR;
}

static const struct hwkey_keyslot test_key_slots[] = {
        {
                .uuid = &hwcrypto_unittest_uuid,
                .key_id = "com.android.trusty.hwcrypto.unittest.key32",
                .handler = get_unittest_key32,
        },
};
#endif /* WITH_HWCRYPTO_UNITTEST */

/*
 * Close specified hwkey context
 */
static void hwkey_ctx_close(struct hwkey_chan_ctx* ctx) {
    close(ctx->chan);
    free(ctx);
}

/*
 * Send response message
 */
static int hwkey_send_rsp(struct hwkey_chan_ctx* ctx,
                          struct hwkey_msg* rsp_hdr,
                          uint8_t* rsp_data,
                          size_t rsp_data_len) {
    rsp_hdr->cmd |= HWKEY_RESP_BIT;
    return tipc_send_two_segments(ctx->chan, rsp_hdr, sizeof(*rsp_hdr),
                                  rsp_data, rsp_data_len);
}

static bool is_allowed_to_read_opaque_key(const uuid_t* uuid,
                                          const struct hwkey_keyslot* slot) {
    assert(slot);
    const struct hwkey_opaque_handle_data* handle = slot->priv;
    assert(handle);

    for (size_t i = 0; i < handle->allowed_uuids_len; ++i) {
        if (memcmp(handle->allowed_uuids[i], uuid, sizeof(uuid_t)) == 0) {
            return true;
        }
    }
    return false;
}

static struct opaque_handle_node* find_opaque_handle_for_slot(
        const struct hwkey_keyslot* slot) {
    struct opaque_handle_node* entry;
    list_for_every_entry(&opaque_handles, entry, struct opaque_handle_node,
                         node) {
        if (entry->key_slot == slot) {
            return entry;
        }
    }

    return NULL;
}

/*
 * If a handle doesn't exist yet for the given slot, create and insert a new one
 * in the global list.
 */
static uint32_t insert_handle_node(struct hwkey_chan_ctx* ctx,
                                   const struct hwkey_keyslot* slot) {
    struct opaque_handle_node* entry = find_opaque_handle_for_slot(slot);

    if (!entry) {
        entry = calloc(1, sizeof(struct opaque_handle_node));
        if (!entry) {
            TLOGE("Could not allocate new opaque_handle_node\n");
            return HWKEY_ERR_GENERIC;
        }

        entry->owner = ctx;
        entry->key_slot = slot;
        list_add_tail(&opaque_handles, &entry->node);
    }

    return HWKEY_NO_ERROR;
}

static uint32_t _handle_slots(struct hwkey_chan_ctx* ctx,
                              const char* slot_id,
                              const struct hwkey_keyslot* slots,
                              unsigned int slot_cnt,
                              uint8_t* kbuf,
                              size_t kbuf_len,
                              size_t* klen) {
    if (!slots)
        return HWKEY_ERR_NOT_FOUND;

    for (unsigned int i = 0; i < slot_cnt; i++, slots++) {
        /* check key id */
        if (strcmp(slots->key_id, slot_id))
            continue;

        /* Check if the caller is allowed to get that key */
        if (memcmp(&ctx->uuid, slots->uuid, sizeof(uuid_t)) == 0) {
            if (slots->handler) {
                if (is_opaque_handle(slots)) {
                    uint32_t rc = insert_handle_node(ctx, slots);
                    if (rc != HWKEY_NO_ERROR)
                        return rc;
                }
                return slots->handler(slots, kbuf, kbuf_len, klen);
            }
        }
    }

    return get_opaque_key(&ctx->uuid, slot_id, kbuf, kbuf_len, klen);
}

/*
 * Handle get key slot command
 */
static int hwkey_handle_get_keyslot_cmd(struct hwkey_chan_ctx* ctx,
                                        struct hwkey_msg* hdr,
                                        const char* slot_id) {
    int rc;
    size_t klen = 0;

    hdr->status = _handle_slots(ctx, slot_id, key_slots, key_slot_cnt, key_data,
                                sizeof(key_data), &klen);

#if WITH_HWCRYPTO_UNITTEST
    if (hdr->status == HWKEY_ERR_NOT_FOUND) {
        /* also search test keys */
        hdr->status = _handle_slots(ctx, slot_id, test_key_slots,
                                    countof(test_key_slots), key_data,
                                    sizeof(key_data), &klen);
    }
#endif

    rc = hwkey_send_rsp(ctx, hdr, key_data, klen);
    if (klen) {
        /* sanitize key buffer */
        memset(key_data, 0, klen);
    }
    return rc;
}

/*
 * Handle Derive key cmd
 */
static int hwkey_handle_derive_key_cmd(struct hwkey_chan_ctx* ctx,
                                       struct hwkey_msg* hdr,
                                       const uint8_t* ikm_data,
                                       size_t ikm_len) {
    int rc;
    size_t key_len = sizeof(key_data);

    /* check requested key derivation function */
    if (hdr->arg1 == HWKEY_KDF_VERSION_BEST)
        hdr->arg1 = HWKEY_KDF_VERSION_1; /* we only support V1 */

    switch (hdr->arg1) {
    case HWKEY_KDF_VERSION_1:
        hdr->status = derive_key_v1(&ctx->uuid, ikm_data, ikm_len, key_data,
                                    &key_len);
        break;

    default:
        TLOGE("%u is unsupported KDF function\n", hdr->arg1);
        key_len = 0;
        hdr->status = HWKEY_ERR_NOT_IMPLEMENTED;
    }

    rc = hwkey_send_rsp(ctx, hdr, key_data, key_len);
    if (key_len) {
        /* sanitize key buffer */
        memset(key_data, 0, key_len);
    }
    return rc;
}

/*
 * Handle Derive key cmd
 */
static int hwkey_handle_mp_dec_cmd(struct hwkey_chan_ctx* ctx,
                                       struct hwkey_msg* hdr,
                                       uint8_t* enc,
                                       size_t size) {

    int rc;
    hdr->status = mp_dec(enc, size, key_data);

    rc = hwkey_send_rsp(ctx, hdr, key_data, size);

    return rc;
}
/*
 *  Read and queue HWKEY request message
 */
static int hwkey_chan_handle_msg(struct hwkey_chan_ctx* ctx) {
    int rc;
    size_t req_data_len;
    struct hwkey_msg hdr;

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
    case HWKEY_GET_KEYSLOT:
        req_data[req_data_len] = 0; /* force zero termination */
        rc = hwkey_handle_get_keyslot_cmd(ctx, &hdr, (const char*)req_data);
        break;

    case HWKEY_DERIVE:
        rc = hwkey_handle_derive_key_cmd(ctx, &hdr, req_data, req_data_len);
        memset(req_data, 0, req_data_len); /* sanitize request buffer */
        break;

    case HWKEY_MP_DEC:
        rc = hwkey_handle_mp_dec_cmd(ctx, &hdr, req_data, req_data_len);
        memset(req_data, 0, req_data_len); /* sanitize request buffer */
        break;

    default:
        TLOGE("Unsupported request: %d\n", (int)hdr.cmd);
        hdr.status = HWKEY_ERR_NOT_IMPLEMENTED;
        rc = hwkey_send_rsp(ctx, &hdr, NULL, 0);
    }

    return rc;
}

/*
 *  HWKEY service channel event handler
 */
static void hwkey_chan_handler(const uevent_t* ev, void* priv) {
    struct hwkey_chan_ctx* ctx = priv;

    assert(ctx);
    assert(ev->handle == ctx->chan);

    tipc_handle_chan_errors(ev);

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        hwkey_ctx_close(ctx);
        return;
    }

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        int rc = hwkey_chan_handle_msg(ctx);
        if (rc < 0) {
            /* report an error and close channel */
            TLOGE("failed (%d) to handle event on channel %d\n", rc,
                  ev->handle);
            hwkey_ctx_close(ctx);
        }
    }
}

/*
 * HWKEY service port event handler
 */
static void hwkey_port_handler(const uevent_t* ev, void* priv) {
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
        struct hwkey_chan_ctx* ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            TLOGE("failed (%d) to allocate context on chan %d\n", rc, chan);
            close(chan);
            return;
        }

        /* init channel state */
        ctx->evt_handler.priv = ctx;
        ctx->evt_handler.proc = hwkey_chan_handler;
        ctx->chan = chan;
        ctx->uuid = peer_uuid;

        rc = set_cookie(chan, &ctx->evt_handler);
        if (rc < 0) {
            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan);
            hwkey_ctx_close(ctx);
            return;
        }
    }
}

/*
 *  Install Key slot provider
 */
void hwkey_install_keys(const struct hwkey_keyslot* keys, unsigned int kcnt) {
    assert(key_slots == NULL);
    assert(key_slot_cnt == 0);
    assert(keys && kcnt);

    key_slots = keys;
    key_slot_cnt = kcnt;
}

static bool is_empty_token(const char* access_token) {
    for (int i = 0; i < HWKEY_OPAQUE_HANDLE_SIZE; i++) {
        if (access_token[i] != 0) {
            assert(strnlen(access_token, HWKEY_OPAQUE_HANDLE_SIZE) ==
                   HWKEY_OPAQUE_HANDLE_SIZE - 1);
            return false;
        }
    }
    return true;
}

uint32_t get_key_handle(const struct hwkey_keyslot* slot,
                        uint8_t* kbuf,
                        size_t kbuf_len,
                        size_t* klen) {
    assert(kbuf);
    assert(klen);

    const struct hwkey_opaque_handle_data* handle = slot->priv;
    assert(handle);
    assert(kbuf_len >= HWKEY_OPAQUE_HANDLE_SIZE);

    struct opaque_handle_node* entry = find_opaque_handle_for_slot(slot);
    /* _handle_slots should have already created an entry for this slot */
    assert(entry);

    if (!is_empty_token(entry->token)) {
        /*
         * We do not allow fetching a token again for the same slot again after
         * the token is first created and returned
         */
        return HWKEY_ERR_ALREADY_EXISTS;
    }

    /*
     * We want to generate a null-terminated opaque handle with no interior null
     * bytes, so we generate extra randomness and only use the non-zero bytes.
     */
    uint8_t random_buf[HWKEY_OPAQUE_HANDLE_SIZE + 2];
    while (1) {
        int rc = hwrng_dev_get_rng_data(random_buf, sizeof(random_buf));
        if (rc != NO_ERROR) {
            /* Don't leave an empty entry if we couldn't generate a token */
            delete_opaque_handle(entry);
            return rc;
        }

        size_t token_offset = 0;
        for (size_t i = 0; i < sizeof(random_buf) &&
                           token_offset < HWKEY_OPAQUE_HANDLE_SIZE - 1;
             ++i) {
            if (random_buf[i] != 0) {
                entry->token[token_offset] = random_buf[i];
                token_offset++;
            }
        }
        if (token_offset == HWKEY_OPAQUE_HANDLE_SIZE - 1) {
            break;
        }
    }

    /* ensure that token is properly null-terminated */
    assert(entry->token[HWKEY_OPAQUE_HANDLE_SIZE - 1] == 0);

    memcpy(kbuf, entry->token, HWKEY_OPAQUE_HANDLE_SIZE);
    *klen = HWKEY_OPAQUE_HANDLE_SIZE;

    return HWKEY_NO_ERROR;
}

uint32_t get_opaque_key(const uuid_t* uuid,
                        const char* access_token,
                        uint8_t* kbuf,
                        size_t kbuf_len,
                        size_t* klen) {
    struct opaque_handle_node* entry;
    list_for_every_entry(&opaque_handles, entry, struct opaque_handle_node,
                         node) {
        /* get_key_handle should never leave an empty token in the list */
        assert(!is_empty_token(entry->token));

        if (!is_allowed_to_read_opaque_key(uuid, entry->key_slot))
            continue;

        /*
         * We are using a constant-time memcmp here to avoid side-channel
         * leakage of the access token. Even if we trust the service that is
         * allowed to retrieve this key, one of its clients may be trying to
         * brute force the token, so this comparison must be constant-time.
         */
        if (CRYPTO_memcmp(entry->token, access_token,
                          HWKEY_OPAQUE_HANDLE_SIZE) == 0) {
            const struct hwkey_opaque_handle_data* handle =
                    entry->key_slot->priv;
            assert(handle);
            return handle->retriever(handle, kbuf, kbuf_len, klen);
        }
    }

    return HWKEY_ERR_NOT_FOUND;
}

/*
 *  Initialize HWKEY service
 */
int hwkey_start_service(void) {
    int rc;
    handle_t port;

    TLOGD("Start HWKEY service\n");

    /* Initialize service */
    rc = port_create(HWKEY_PORT, 1,
                     sizeof(struct hwkey_msg) + HWKEY_MAX_PAYLOAD_SIZE,
                     IPC_PORT_ALLOW_TA_CONNECT);
    if (rc < 0) {
        TLOGE("Failed (%d) to create port %s\n", rc, HWKEY_PORT);
        return rc;
    }

    port = (handle_t)rc;
    rc = set_cookie(port, &hwkey_port_evt_handler);
    if (rc) {
        TLOGE("failed (%d) to set_cookie on port %d\n", rc, port);
        close(port);
        return rc;
    }

    return NO_ERROR;
}
