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
 * Copyright 2023 NXP
 */

#define TLOG_TAG "hwcrypto_srv"

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
#include "hwkey_srv_priv.h"
#include <nxp_hwcrypto_uuid_consts.h>
#include <lib/storage/storage.h>
#include <trusty_log.h>
#include <lib/rng/trusty_rng.h>

#define HWCRYPTO_MAX_PAYLOAD_SIZE 2048
static bool boot_state_locked = false;

#define RPMB_EMMC_CID_SIZE 16
bool emmc_cid_provisioned = false;
uint8_t emmc_cid[RPMB_EMMC_CID_SIZE] __attribute__((aligned(16)));

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

    /* canculate hash */
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

    /* encapsulate the text located in msg->plain_pa with length
     * 'size', generated blob will be stored to msg->blob_pa.
     */
    hdr->status = encap_blob(msg->plain_pa,
                             msg->plain_size, msg->blob_pa);

fail:
    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

/*
 * Handle rng generate command
 */
static int hwcrypto_gen_rng(struct hwcrypto_chan_ctx* ctx,
                               struct hwcrypto_msg* hdr,
                               uint8_t *req_data,
                               size_t req_data_len)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    int rc = 0;

    assert(hdr);
    assert(req_data);

    /* sanity check the req length */
    if (req_data_len < sizeof(hwcrypto_rng_req)) {
        hdr->status = HWCRYPTO_ERROR_INVALID;
        goto exit;
    }

    hwcrypto_rng_req *msg = (hwcrypto_rng_req *)req_data;
    if (msg->len == 0) {
        TLOGE("Invalid length for RNG request!\n");
        hdr->status = HWCRYPTO_ERROR_INVALID;
        goto exit;
    }

    buf = malloc(msg->len);
    if (!buf) {
        TLOGE("allocate memory failed!\n");
        hdr->status = HWCRYPTO_ERROR_INVALID;
        goto exit;
    }
    /* generate 'len' length rng and put it into 'buf'.
     */
    if (trusty_rng_secure_rand(buf, msg->len)) {
        TLOGE("failed to generate RNG!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }
    len = msg->len;
    hdr->status = HWCRYPTO_ERROR_NONE;

exit:
    rc = hwcrypto_send_rsp(ctx, hdr, buf, len);

    if (buf)
        free(buf);
    return rc;
}

/*
 * Handle huk generate command
 */
static int hwcrypto_gen_bkek(struct hwcrypto_chan_ctx* ctx,
                               struct hwcrypto_msg* hdr,
                               uint8_t *req_data,
                               size_t req_data_len)
{
    assert(hdr);
    assert(req_data);

    /* sanity check the req length */
    if (req_data_len < sizeof(hwcrypto_bkek_msg)) {
        hdr->status = HWCRYPTO_ERROR_INVALID;
        goto fail;
    }

    hwcrypto_bkek_msg *msg = (hwcrypto_bkek_msg *)req_data;
    if (msg->buf == 0) {
        hdr->status = HWCRYPTO_ERROR_INVALID;
        goto fail;
    }

    /* generate 'len' length rng and put it into 'buf'.
     */
#if ENABLE_BKEK_GENERATION
    hdr->status = gen_bkek(msg->buf, msg->len);
#else
    TLOGE("Error, please set 'ENABLE_BKEK_GENERATION' to generate bkek with CAAM.\n");
    hdr->status = HWCRYPTO_ERROR_INVALID;
#endif

fail:
    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

static const char* WvKeyBoxFilename = "wv.keybox";
static int write_wv_key(uint8_t *data, uint32_t data_size) {
    int rc = 0;
    storage_session_t session;
    file_handle_t file_handle;
    storage_off_t file_size = 0;

    /* write the wv key to secure storage */
    /* connect to secure storage TA */
    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("hwcrypto: failed to connect to storage TA: %d!\n", rc);
        return rc;
    }

    /* open file in secure storage */
    rc = storage_open_file(session, &file_handle, WvKeyBoxFilename, STORAGE_FILE_OPEN_CREATE, 0);
    if (rc < 0) {
        TLOGE("hwcrypto: failed to open keybox: %d!\n", rc);
        storage_close_session(session);
        return rc;
    }

    /* check if the keybox has been set before */
    if (storage_get_file_size(file_handle, &file_size) < 0 || file_size != 0) {
        TLOGE("hwcrypto: failed to get file size or the keybox has been provisioned!\n");
        storage_close_file(file_handle);
        storage_close_session(session);
        return -1;
    }

    /* now do the write operation */
    rc = storage_write(file_handle, 0, data, data_size, STORAGE_OP_COMPLETE);
    storage_close_file(file_handle);
    storage_close_session(session);

    if (rc < 0 || rc != (int)data_size) {
        TLOGE("hwcrypto: keybox write failed!\n");
        return -1;
    } else {
        return 0;
    }
}

static int hwcrypto_provision_wv_key(struct hwcrypto_chan_ctx* ctx,
                                     struct hwcrypto_msg* hdr,
                                     uint8_t *req_data,
                                     size_t req_data_len)
{
    uint8_t *data = NULL;
    uint32_t data_size;
    int rc = 0;

    /* sanity check */
    assert(hdr);
    assert(req_data);

   /* The wv key request should be "data_size + data" */
    data_size = *((uint32_t *)req_data);
    data = (uint8_t *)(req_data + sizeof(data_size));

    rc = write_wv_key(data, data_size);
    if (rc < 0)
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
    else
        hdr->status = HWCRYPTO_ERROR_NONE;

    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

static int hwcrypto_provision_wv_key_enc(struct hwcrypto_chan_ctx* ctx,
                                         struct hwcrypto_msg* hdr,
                                         uint8_t *req_data,
                                         size_t req_data_len) {
    uint8_t *enc_data;
    uint32_t enc_data_size;
    struct wv_blob_header *header;
    int rc = 0;
    uint8_t data[HWCRYPTO_MAX_PAYLOAD_SIZE];

    /* sanity check */
    assert(hdr);
    assert(req_data);

   /* The wv key request should be "data_size + wv_blob_header + data" */
    enc_data_size = *((uint32_t *)req_data);
    header = (struct wv_blob_header *)(req_data + sizeof(enc_data_size));
    enc_data = (uint8_t *)(req_data + sizeof(struct wv_blob_header) + sizeof(enc_data_size));

    if (memcmp(BLOB_HEADER_MAGIC, header->magic, sizeof(BLOB_HEADER_MAGIC))) {
        TLOGE("wv header magic doesn't match!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto fail;
    }

    /* perform wv keybox decryption */
    if (mp_dec(enc_data, enc_data_size - sizeof(struct wv_blob_header), data)) {
        TLOGE("failed to decrypt wv keybox!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto fail;
    }

    /* write to secure storage */
    rc = write_wv_key(data, header->len);
    if (rc < 0)
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
    else
        hdr->status = HWCRYPTO_ERROR_NONE;

fail:
    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

static int hwcrypto_set_emmc_cid(struct hwcrypto_chan_ctx* ctx,
                                 struct hwcrypto_msg* hdr,
                                 uint8_t *req_data,
                                 size_t req_data_len) {
    uint32_t cid_size;

    /* sanity check */
    assert(hdr);
    assert(req_data);

   /* The cid request should be "data_size + data" */
    cid_size = *((uint32_t *)req_data);
    if (cid_size != RPMB_EMMC_CID_SIZE) {
        TLOGE("wrong input dek size!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;

        goto exit;
    }
    memcpy(emmc_cid, req_data + sizeof(cid_size), RPMB_EMMC_CID_SIZE);

    emmc_cid_provisioned = true;
    hdr->status = HWCRYPTO_ERROR_NONE;

exit:
    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

#ifdef WITH_CAAM_SUPPORT
static int hwcrypto_gen_dek_blob(struct hwcrypto_chan_ctx* ctx,
                                 struct hwcrypto_msg* hdr,
                                 uint8_t *req_data,
                                 size_t req_data_len) {
    uint8_t *dek = NULL, *blob = NULL;
    uint32_t dek_size, blob_size = 0;
    uint32_t rc = 0;

    assert(hdr);
    assert(req_data);

    /* The payload format should be 'dek' + 'dek_size' */
    dek_size = *((uint32_t *)req_data);
    dek = req_data + sizeof(uint32_t);

    /* sanity check the dek size */
    if ((dek_size != 16) && (dek_size != 24) && (dek_size != 32)) {
        TLOGE("wrong input dek size!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    blob_size = dek_size + CAAM_KB_HEADER_LEN + HAB_DEK_BLOB_HEADER_LEN;
    blob = malloc(blob_size);
    if (!blob) {
        TLOGE("failed to allocate dek blob memory!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    if (caam_gen_dek_blob(dek, dek_size, blob)) {
        TLOGE("failed to generate dek blob!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }
    hdr->status = HWCRYPTO_ERROR_NONE;

exit:
    rc = hwcrypto_send_rsp(ctx, hdr, blob, blob_size);

    if (blob)
        free(blob);
    return rc;
}
#endif

static const char* FirmwareSignKeyFilename = "firmware.sign.key";
static const char* FirmwareEncryptKeyFilename = "firmware.encrypt.key";
static int write_firmware_key(uint8_t *data, uint32_t data_size, bool sign) {
    int rc = 0;
    storage_session_t session;
    file_handle_t file_handle;
    storage_off_t file_size = 0;

    if ((data_size == 0) || (data_size > 4096)) {
        TLOGE("firmware key is invalid\n");
        return -1;
    }

    /* write the wv key to secure storage */
    /* connect to secure storage TA */
    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("hwcrypto: failed to connect to storage TA: %d!\n", rc);
        return rc;
    }

    /* open file in secure storage */
    if (sign) {
        rc = storage_open_file(session, &file_handle, FirmwareSignKeyFilename, STORAGE_FILE_OPEN_CREATE, 0);
    } else {
        rc = storage_open_file(session, &file_handle, FirmwareEncryptKeyFilename, STORAGE_FILE_OPEN_CREATE, 0);
    }
    if (rc < 0) {
        TLOGE("hwcrypto: failed to open firmware sign=%d key: %d!\n", sign, rc);
        storage_close_session(session);
        return rc;
    }

    /* check if the keybox has been set before */
    if (storage_get_file_size(file_handle, &file_size) < 0 || file_size != 0) {
        TLOGE("hwcrypto: failed to get file size or the firmware sign=%d key has been provisioned!\n", sign);
        storage_close_file(file_handle);
        storage_close_session(session);
        return -1;
    }

    /* now do the write operation */
    rc = storage_write(file_handle, 0, data, data_size, STORAGE_OP_COMPLETE);
    storage_close_file(file_handle);
    storage_close_session(session);

    if (rc < 0 || rc != (int)data_size) {
        TLOGE("hwcrypto: firmware %s key write failed!\n", (sign? "sign": "encrypt"));
        return -1;
    } else {
        return 0;
    }
}

static int hwcrypto_provision_firmware_sign_key(struct hwcrypto_chan_ctx* ctx,
                                                struct hwcrypto_msg* hdr,
                                                uint8_t *req_data,
                                                size_t req_data_len)
{
    uint8_t *data = NULL;
    uint32_t data_size;
    int rc = 0;

    /* sanity check */
    assert(hdr);
    assert(req_data);

   /* The wv key request should be "data_size + data" */
    data_size = *((uint32_t *)req_data);
    data = (uint8_t *)(req_data + sizeof(data_size));

    rc = write_firmware_key(data, data_size, true);
    if (rc < 0)
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
    else
        hdr->status = HWCRYPTO_ERROR_NONE;

    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

static int hwcrypto_provision_firmware_encrypt_key(struct hwcrypto_chan_ctx* ctx,
                                                   struct hwcrypto_msg* hdr,
                                                   uint8_t *req_data,
                                                   size_t req_data_len)
{
    uint8_t *data = NULL;
    uint32_t data_size;
    int rc = 0;

    /* sanity check */
    assert(hdr);
    assert(req_data);

   /* The wv key request should be "data_size + data" */
    data_size = *((uint32_t *)req_data);
    data = (uint8_t *)(req_data + sizeof(data_size));

    rc = write_firmware_key(data, data_size, false);
    if (rc < 0)
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
    else
        hdr->status = HWCRYPTO_ERROR_NONE;

    return hwcrypto_send_rsp(ctx, hdr, NULL, 0);
}

static int hwcrypto_provision_dek_blob(struct hwcrypto_chan_ctx* ctx,
                                     struct hwcrypto_msg* hdr,
                                     uint8_t *req_data,
                                     size_t req_data_len) {
    storage_session_t session = 0;
    file_handle_t file_handle = 0;
    storage_off_t file_size = 0;
    uint8_t *dek_blob = NULL;
    uint32_t dek_blob_size;
    const char* DekBlobFilename = NULL;
    int rc = 0;

    dek_blob_size = *((uint32_t *)req_data);
    dek_blob = req_data + sizeof(uint32_t);

    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("hwcrypto: failed to connect to storage TA: %d!\n", rc);
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    if (hdr -> cmd == HWCRYPTO_PROVISION_SPL_DEK_BLOB)
        DekBlobFilename = "spl_dek.key";
    else if (hdr -> cmd == HWCRYPTO_PROVISION_BOOTLOADER_DEK_BLOB)
        DekBlobFilename = "bootloader_dek.key";
    else {
        TLOGE("hwcrypto: Wrong command!\n");
        goto exit;
    }

    rc = storage_open_file(session, &file_handle, DekBlobFilename, STORAGE_FILE_OPEN_CREATE, 0);
    if (rc < 0) {
        TLOGE("hwcrypto: failed to open keybox: %d!\n", rc);
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    if (storage_get_file_size(file_handle, &file_size) && file_size) {
        TLOGE("hwcrypto: dek blob already exists, will be overwritten!\n");
    }

    rc = storage_write(file_handle, 0, dek_blob, dek_blob_size, STORAGE_OP_COMPLETE);
    if (rc < 0 || rc != (int)dek_blob_size) {
        TLOGE("hwcrypto: %s write failed!\n", DekBlobFilename);
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    } else {
        TLOGE("hwcrypto: %s write successfully!\n", DekBlobFilename);
        hdr->status = HWCRYPTO_ERROR_NONE;
        goto exit;
    }

exit:
    if (file_handle)
        storage_close_file(file_handle);
    if (session)
        storage_close_session(session);
    rc = hwcrypto_send_rsp(ctx, hdr, NULL, 0);
    return rc;
}

static int hwcrypto_get_dek_blob_info(struct hwcrypto_chan_ctx* ctx,
                                       struct hwcrypto_msg* hdr) {
    storage_session_t session = 0;
    file_handle_t file_handle = 0;
    uint8_t *dek_blob = NULL;
    storage_off_t dek_blob_size = 0;
    uint32_t dek_size = 0;
    const char *DekBlobFilename;
    int rc = 0;

    /* connect to secure storage TA */
    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("hwkey: failed to connect to storage TA!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    switch (hdr -> cmd) {
    case HWCRYPTO_GET_SPL_DEK_BLOB:
    case HWCRYPTO_GET_SPL_DEK_BLOB_SIZE:
        DekBlobFilename = "spl_dek.key";
        break;
    case HWCRYPTO_GET_BOOTLOADER_DEK_BLOB:
    case HWCRYPTO_GET_BOOTLOADER_DEK_BLOB_SIZE:
        DekBlobFilename = "bootloader_dek.key";
        break;
    default:
        TLOGE("hwkey: mismatched command!\n");
        goto exit;
    }
    TLOGE("hwkey: Attempting to extract dek-blob: %s\n", DekBlobFilename);

    /* open file in secure storage */
    rc = storage_open_file(session, &file_handle, DekBlobFilename, 0, 0);
    if (rc < 0) {
        TLOGE("hwkey: failed to open %s!\n", DekBlobFilename);
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    /* get dek blob size */
    rc = storage_get_file_size(file_handle, &dek_blob_size);
    if (rc < 0) {
        TLOGE("hwkey: failed to get dek blob size!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    } else {
        dek_size = dek_blob_size - CAAM_KB_HEADER_LEN - HAB_DEK_BLOB_HEADER_LEN;
        if ((dek_size != 16) && (dek_size != 24) && (dek_size != 32)) {
            TLOGE("wrong dek size!\n");
            hdr->status = HWCRYPTO_ERROR_INTERNAL;
            goto exit;
        }
    }

    if ( hdr -> cmd == HWCRYPTO_GET_SPL_DEK_BLOB || hdr -> cmd == HWCRYPTO_GET_BOOTLOADER_DEK_BLOB ) {
        /* read the dek-blob */
        dek_blob = malloc(dek_blob_size);
        if (!dek_blob) {
            TLOGE("hwkey: memory allocation failed!\n");
            goto exit;
        }

        rc = storage_read(file_handle, 0, (uint8_t*)dek_blob, dek_blob_size);
        if (rc < 0) {
            TLOGE("hwkey: failed to read dek blob!\n");
            hdr->status = HWCRYPTO_ERROR_INTERNAL;
            goto exit;
        }
    }

    hdr->status = HWCRYPTO_ERROR_NONE;

    switch (hdr -> cmd) {
    case HWCRYPTO_GET_SPL_DEK_BLOB_SIZE:
    case HWCRYPTO_GET_BOOTLOADER_DEK_BLOB_SIZE:
        rc = hwcrypto_send_rsp(ctx, hdr, (uint8_t*)(&dek_blob_size), sizeof(uint32_t));
        break;
    case HWCRYPTO_GET_SPL_DEK_BLOB:
    case HWCRYPTO_GET_BOOTLOADER_DEK_BLOB:
        rc = hwcrypto_send_rsp(ctx, hdr, (uint8_t*)(dek_blob), dek_blob_size);
        break;
    default:
        TLOGE("hwkey: mismatched command!\n");
        hdr->status = HWCRYPTO_ERROR_INTERNAL;
        goto exit;
    }

    if (rc < 0) {
        TLOGE("hwkey: dek blob send failed!\n");
    } else {
        TLOGE("hwkey: dek blob send successfully!\n");
    }

exit:
    if (dek_blob)
        free(dek_blob);
    if (file_handle)
        storage_close_file(file_handle);
    if (session)
        storage_close_session(session);
    if (hdr->status != HWCRYPTO_ERROR_NONE)
        hwcrypto_send_rsp(ctx, hdr, NULL, 0);
    return rc;
}

static bool check_whitelist(enum hwcrypto_cmd cmd)
{
    uint32_t count = 0;
    enum hwcrypto_cmd whitelist[] = {
        HWCRYPTO_GET_SPL_DEK_BLOB,
        HWCRYPTO_GET_SPL_DEK_BLOB_SIZE,
        HWCRYPTO_GET_BOOTLOADER_DEK_BLOB,
        HWCRYPTO_GET_BOOTLOADER_DEK_BLOB_SIZE,
    };

    while (count < sizeof(whitelist)/sizeof(enum hwcrypto_cmd))
    {
        if (cmd != whitelist[count])
            count++;
        else
            return true;
    }
    return false;
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

    if (!check_whitelist(hdr.cmd) && boot_state_locked) {
        hdr.status = HWCRYPTO_ERROR_NONE;
        TLOGE("Can't execute hwcrypto commands when boot state is locked.\n");
        rc = hwcrypto_send_rsp(ctx, &hdr, NULL, 0);
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

    case HWCRYPTO_GEN_RNG:
        rc = hwcrypto_gen_rng(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_GEN_BKEK:
        rc = hwcrypto_gen_bkek(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_LOCK_BOOT_STATE:
        boot_state_locked = true;
        hdr.status = HWCRYPTO_ERROR_NONE;
        rc = hwcrypto_send_rsp(ctx, &hdr, NULL, 0);
        break;

    case HWCRYPTO_PROVISION_WV_KEY:
        rc = hwcrypto_provision_wv_key(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_PROVISION_WV_KEY_ENC:
        rc = hwcrypto_provision_wv_key_enc(ctx, &hdr, req_data, req_data_len);
        break;

#ifdef WITH_CAAM_SUPPORT
    case HWCRYPTO_GEN_DEK_BLOB:
        rc = hwcrypto_gen_dek_blob(ctx, &hdr, req_data, req_data_len);
        break;
#endif

    case HWCRYPTO_SET_EMMC_CID:
        rc = hwcrypto_set_emmc_cid(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_PROVISION_FIRMWARE_SIGN_KEY:
        rc = hwcrypto_provision_firmware_sign_key(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_PROVISION_FIRMWARE_ENCRYPT_KEY:
        rc = hwcrypto_provision_firmware_encrypt_key(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_PROVISION_SPL_DEK_BLOB:
    case HWCRYPTO_PROVISION_BOOTLOADER_DEK_BLOB:
        rc = hwcrypto_provision_dek_blob(ctx, &hdr, req_data, req_data_len);
        break;

    case HWCRYPTO_GET_SPL_DEK_BLOB:
    case HWCRYPTO_GET_SPL_DEK_BLOB_SIZE:
    case HWCRYPTO_GET_BOOTLOADER_DEK_BLOB:
    case HWCRYPTO_GET_BOOTLOADER_DEK_BLOB_SIZE:
        rc = hwcrypto_get_dek_blob_info(ctx, &hdr);
        break;

    default:
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

    TLOGD("Start HWCRYPTO service\n");

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
