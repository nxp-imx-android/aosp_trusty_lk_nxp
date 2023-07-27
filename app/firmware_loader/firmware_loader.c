/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define TLOG_TAG "firmware_loader"

#include <assert.h>
#include <endian.h>
#include <interface/firmware_loader/firmware_loader.h>
#include <inttypes.h>
#include <lib/system_state/system_state.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <lk/macros.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <uapi/mm.h>
#include <trusty_log.h>
#include "nxp_memmap_consts.h"
#include "firmware_loader_package.h"
#include <trusty/sys/mman.h>
#include <platform/imx_amphion.h>
#include <sys/ioctl.h>
#include <lib/syscall.h>
#include <platform/imx_scu.h>

extern long _trusty_ioctl(uint32_t fd, uint32_t req, void *buf);

struct firmware_loader_req {
    struct firmware_loader_header hdr;
    union {
        struct firmware_loader_load_firm_req load_firm_req;
    };
} __PACKED;

/*
 * Common structure covering all possible firmware loader messages, only used to
 * determine the maximum message size
 */
union firmware_loader_longest_msg {
    struct firmware_loader_req req;
    struct firmware_loader_resp resp;
} __PACKED;

static struct tipc_port_acl firmware_loader_port_acl = {
        .flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT,
        .uuid_num = 0,
        .uuids = NULL,
        .extra_data = NULL,
};

static struct tipc_port firmware_loader_port = {
        .name = FIRMWARELOADER_PORT,
        .msg_max_size = sizeof(union firmware_loader_longest_msg),
        .msg_queue_len = 1,
        .acl = &firmware_loader_port_acl,
        .priv = NULL,
};

static int apploader_translate_error(int rc) {
    if (rc > 0) {
        return FIRMWARELOADER_ERR_INTERNAL;
    }

    switch (rc) {
    case ERR_NO_MEMORY:
        return FIRMWARELOADER_ERR_NO_MEMORY;
    case ERR_ALREADY_EXISTS:
        return FIRMWARELOADER_ERR_ALREADY_EXISTS;
    default:
        TLOGW("Unrecognized error (%d)\n", rc);
        return FIRMWARELOADER_ERR_INTERNAL;
    }
}

static int firmware_loader_send_response(handle_t chan,
                                   uint32_t cmd,
                                   uint32_t error) {
    struct firmware_loader_resp resp = {
            .hdr =
                    {
                            .cmd = cmd | FIRMLOADER_RESP_BIT,
                    },
            .error = error,
    };
    int rc = tipc_send1(chan, &resp, sizeof(resp));
    if (rc < 0) {
        return rc;
    }

    if ((size_t)rc != sizeof(resp)) {
        TLOGE("Failed to send message (%d). Expected to send %zu bytes.\n", rc,
              sizeof(resp));
        return ERR_BAD_LEN;
    }
    return NO_ERROR;
}

static int firmware_loader_read(handle_t chan,
                          size_t min_sz,
                          void* buf,
                          size_t buf_sz,
                          handle_t* handles,
                          uint32_t* num_handles) {
    int rc;
    ipc_msg_info_t msg_inf;
    rc = get_msg(chan, &msg_inf);
    if (rc != NO_ERROR) {
        TLOGE("Failed to get message (%d)\n", rc);
        return rc;
    }

    if (msg_inf.len < min_sz || msg_inf.len > buf_sz) {
        TLOGE("Message is too short or too long (%zd)\n", msg_inf.len);
        rc = ERR_BAD_LEN;
        goto err;
    }

    uint32_t max_num_handles = num_handles ? *num_handles : 0;
    if (msg_inf.num_handles > max_num_handles) {
        TLOGE("Message has too many handles (%" PRIu32 ")\n",
              msg_inf.num_handles);
        rc = ERR_TOO_BIG;
        goto err;
    }

    struct iovec iov = {
            .iov_base = buf,
            .iov_len = buf_sz,
    };
    ipc_msg_t ipc_msg = {
            .iov = &iov,
            .num_iov = 1,
            .handles = handles,
            .num_handles = msg_inf.num_handles,
    };
    rc = read_msg(chan, msg_inf.id, 0, &ipc_msg);
    assert(rc < 0 || (size_t)rc == msg_inf.len);

    if (rc >= 0 && num_handles) {
        *num_handles = msg_inf.num_handles;
    }

err:
    put_msg(chan, msg_inf.id);
    return rc;
}

static bool load_to_secure_memory(
        struct firmware_loader_package_metadata* pkg_meta) {
    if (pkg_meta->elf_start > pkg_meta->manifest_start) {
        /*
         * For now, we only support input files where the ELF precedes
         * the manifest. The current file format follows this rule.
         */
        return false;
    }

    /* mmap secure firmare boot buffer */
    void* secure_boot_buffer = NULL;
    secure_boot_buffer = mmap(NULL, FIRMWARE_BOOT_SIZE, PROT_READ | PROT_WRITE, MMAP_FLAG_IO_HANDLE, FIRMWARE_BOOT_MMIO_ID, 0);
    if (secure_boot_buffer == MAP_FAILED) {
        TLOGE("secure_boot_buffer mmap failed\n");
        return -1;
    }

    uint64_t unaligned_elf_size = pkg_meta->elf_size;
    memcpy(secure_boot_buffer, pkg_meta->elf_start, unaligned_elf_size);

    /* flush cache to dram */
    struct dma_pmem pmem;
    int ret = prepare_dma(secure_boot_buffer, FIRMWARE_BOOT_SIZE, DMA_FLAG_FROM_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return false;
    }

    /* unmmap secure boot buffer */
    munmap(secure_boot_buffer, FIRMWARE_BOOT_SIZE);

    return true;
}

static uint32_t firmware_loader_copy_package(handle_t req_handle,
                                       uint64_t aligned_size,
                                       uint8_t** out_package) {
    uint32_t resp_error;

    void* req_package = mmap(NULL, aligned_size, PROT_READ, 0, req_handle, 0);
    if (req_package == MAP_FAILED) {
        TLOGE("Failed to map the request handle\n");
        resp_error = FIRMWARELOADER_ERR_NO_MEMORY;
        goto err_req_mmap;
    }

    void* resp_package = NULL;
    resp_package = malloc(aligned_size);
    if (resp_package == NULL) {
        TLOGE("resp_package failed alloc\n");
        resp_error = FIRMWARELOADER_ERR_NO_MEMORY;
    } else {

        assert(out_package);
        memcpy(resp_package, req_package, aligned_size);
        *out_package = resp_package;
        resp_error = FIRMWARELOADER_NO_ERROR;
    }

err_resp_mmap:
    munmap(req_package, aligned_size);
err_req_mmap:
err_invalid_secure_mem_handle:
err_send_get_memory:
    return resp_error;
}

static int firmware_loader_handle_cmd_load_firmware(handle_t chan,
                                                    struct firmware_loader_load_firm_req* req,
                                                    handle_t req_handle) {
    uint32_t resp_error = 0;

    if (req_handle == INVALID_IPC_HANDLE) {
        TLOGE("Received invalid request handle\n");
        resp_error =FIRMWARELOADER_ERR_INVALID_CMD;
        goto err_invalid_req_handle;
    }

    uint64_t page_size = getauxval(AT_PAGESZ);
    uint64_t aligned_size = round_up(req->package_size, page_size);
    TLOGD("Loading %" PRIu64 " bytes package, %" PRIu64 " aligned\n",
          req->package_size, aligned_size);

    uint32_t copy_error;
    uint8_t* package;
    copy_error = firmware_loader_copy_package(req_handle, aligned_size, &package);
    if (copy_error != FIRMWARELOADER_NO_ERROR) {
        TLOGE("Failed to copy package from client\n");
        resp_error = copy_error;
        goto err_copy_package;
    }

    struct firmware_loader_package_metadata pkg_meta = {0};
    if (!firmware_loader_parse_package_metadata(package, req->package_size,
                                          &pkg_meta)) {
        TLOGE("Failed to parse application package\n");
        resp_error = FIRMWARELOADER_ERR_VERIFICATION_FAILED;
        goto err_invalid_package;
    }

    if (!pkg_meta.manifest_start || !pkg_meta.manifest_size) {
        TLOGE("Could not find manifest in application package\n");
        resp_error = FIRMWARELOADER_ERR_VERIFICATION_FAILED;
        goto err_manifest_not_found;
    }

    if (!pkg_meta.elf_start || !pkg_meta.elf_size) {
        TLOGE("Could not find ELF image in application package\n");
        resp_error = FIRMWARELOADER_ERR_VERIFICATION_FAILED;
        goto err_elf_not_found;
    }

    int ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_SCU, SCU_POWER_ON_VPU, NULL);
    if (!ret) {
        ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_AMPHION, AMPHION_GET_FIRMWARE_POWER, NULL);
        if (!ret) {
            ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_AMPHION, AMPHION_CLEAR_BOOT_BUFFER, NULL);
            if (ret) {
                TLOGE(" AMPHION_CLEAR_BOOT_BUFFER failed\n");
                goto err_invalid_boot_buffer;
            }
            load_to_secure_memory(&pkg_meta);
            TLOGE(" secure firmware load into secure memory\n ");
        }
    } else {
        TLOGE(" VPU power on failed, can't load secure firmware\n ");
    }
err_invalid_boot_buffer:
err_elf_not_found:
err_manifest_not_found:
err_invalid_package:
    if (pkg_meta.public_key) {
        free((void*)pkg_meta.public_key);
    }

    if (package) {
        free(package);
    }
err_copy_package:
err_invalid_req_handle:
    return firmware_loader_send_response(chan, FIRMLOADER_CMD_LOAD_FIRMWARE,
                                   resp_error);
}

static int firmware_loader_on_message(const struct tipc_port* port,
                                handle_t chan,
                                void* ctx) {
    assert(port == &firmware_loader_port);
    assert(ctx == NULL);
    int rc;
    handle_t handle = INVALID_IPC_HANDLE;
    uint32_t num_handles = 1;
    struct firmware_loader_req req;
    rc = firmware_loader_read(chan, sizeof(req.hdr), &req, sizeof(req), &handle,
                              &num_handles);
    if (rc < 0) {
        TLOGE("Failed to read request (%d)\n", rc);
        return rc;
    }

    TLOGD("Command: 0x%x\n", req.hdr.cmd);

    size_t cmd_len;
    switch (req.hdr.cmd) {
    case FIRMLOADER_CMD_LOAD_FIRMWARE:
        /* Check the message length */
        cmd_len = sizeof(req.hdr) + sizeof(req.load_firm_req);
        if (rc != (int)cmd_len) {
            TLOGE("Expected to read %zu bytes, got %d.\n", cmd_len, rc);
            rc = firmware_loader_send_response(chan, req.hdr.cmd,
                                         FIRMWARELOADER_ERR_INVALID_CMD);
            break;
        }

        if (num_handles != 1) {
            TLOGE("Expected 1 handle, got %" PRIu32 "\n", num_handles);
            rc = firmware_loader_send_response(chan, req.hdr.cmd,
                                         FIRMWARELOADER_ERR_INVALID_CMD);
            break;
        }

        rc = firmware_loader_handle_cmd_load_firmware(chan, &req.load_firm_req, handle);
        break;

    default:
        TLOGE("Received unknown firmware loader command: %" PRIu32 "\n", req.hdr.cmd);
        rc = firmware_loader_send_response(chan, req.hdr.cmd,
                                     FIRMWARELOADER_ERR_UNKNOWN_CMD);
        break;
    }

    if (rc < 0) {
        TLOGE("Failed to run command (%d)\n", rc);
    }

    if (handle != INVALID_IPC_HANDLE) {
        close(handle);
    }

    return rc;
}

static struct tipc_srv_ops firmware_loader_ops = {
        .on_message = firmware_loader_on_message,
};

int main(void) {
    struct tipc_hset* hset = tipc_hset_create();

    if (IS_ERR(hset)) {
        return PTR_ERR(hset);
    }

    int rc = tipc_add_service(hset, &firmware_loader_port, 1, 1, &firmware_loader_ops);
    if (rc < 0) {
        return rc;
    }

    rc = tipc_run_event_loop(hset);
    printf("firmware loader going down: (%d)\n", rc);
    return rc;
}
