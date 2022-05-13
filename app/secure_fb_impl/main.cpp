/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2021 NXP
 *
 */

#include <lib/secure_fb/srv/dev.h>
#include <lib/secure_fb/srv/srv.h>
#include <lib/tipc/tipc.h>
#include <lk/err_ptr.h>
#include <lk/macros.h>
#include <lk/reg.h>
#include <memref.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <platform/imx_csu.h>
#include <lib/hwsecure/hwsecure.h>
#include <tuple>
#include <imx-regs.h>
#include <nxp_confirmationui_consts.h>

#define TLOG_TAG "secure_fb_impl"

#define PAGE_SIZE() (getauxval(AT_PAGESZ))

static constexpr const uint32_t kFbCount = 1;
static constexpr const uint32_t kFbId = 0xdeadbeef;

#define INVALID_HANDLE (handle_t)(-1)

extern "C" long _trusty_ioctl(uint32_t fd, uint32_t req, void *buf);

class SecureFbImpl {
private:
    struct FbDbEntry {
        secure_fb_info fb_info;
        handle_t handle = INVALID_HANDLE;
        ptrdiff_t offset;
    };

    FbDbEntry fb_db_[kFbCount];

public:
    ~SecureFbImpl() {
        struct csu_cfg_secure_disp_msg msg;

        close((handle_t)fb_db_[0].handle);
        free(fb_db_[0].fb_info.buffer);

        msg.enable = 0;
        msg.paddr = 0;
        _trusty_ioctl(SYSCALL_PLATFORM_FD_CSU, CSU_IOCMD_SECURE_DISP, &msg);
#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM)
        set_lcdif_secure_access(false);
#endif
    }

    int Init(uint32_t width, uint32_t height) {

        uint32_t fb_size =
                round_up(sizeof(uint32_t) * width * height, PAGE_SIZE());

        void* fb_base = memalign(PAGE_SIZE(), fb_size);
        if (!fb_base) {
            TLOGE("Failed to allocate framebuffer of size: %u\n", fb_size);
            return SECURE_FB_ERROR_MEMORY_ALLOCATION;
        }

        /*
         * Create a handle for the buffer by which it can be passed to the TUI
         * app for rendering.
         */
        int handle =
                memref_create(fb_base, fb_size, PROT_READ | PROT_WRITE);
        if (handle < 0) {
            TLOGE("Failed to create memref (%d)\n", handle);
            return SECURE_FB_ERROR_SHARED_MEMORY;
        }

        fb_db_[0] = {
                .fb_info =
                        {
                                .buffer = (uint8_t*)fb_base,
                                .size = fb_size,
                                .pixel_stride = 4,
                                .line_stride = 4 * width,
                                .width = width,
                                .height = height,
                                .pixel_format = TTUI_PF_RGBA8,
                        },
                .handle = handle,
        };

        return SECURE_FB_ERROR_OK;
    }

    int GetFbs(struct secure_fb_impl_buffers* buffers) {
        TLOGE("TRACING GetFbs...\n");
        *buffers = {
                .num_fbs = 1,
                .fbs[0] =
                        {
                                .buffer_id = kFbId,
                                .handle_index = 0,
                                .fb_info = fb_db_[0].fb_info,
                        },
                .num_handles = 1,
                .handles[0] = fb_db_[0].handle,
        };
        return SECURE_FB_ERROR_OK;
    }

    int Display(uint32_t buffer_id) {
        struct dma_pmem pmem;
        uint8_t *fb_base;
        size_t fb_size;
        uint32_t paddr;

        if (buffer_id != kFbId) {
            TLOGE("TRACING Display error!!!\n");
            return SECURE_FB_ERROR_INVALID_REQUEST;
        }

        fb_base = fb_db_[0].fb_info.buffer;
        fb_size = fb_db_[0].fb_info.size;
        prepare_dma(fb_base, fb_size, DMA_FLAG_TO_DEVICE, &pmem);
        paddr = (uint32_t)pmem.paddr;
#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM)
        set_lcdif_secure_access(true);
#endif
        struct csu_cfg_secure_disp_msg msg;
        msg.enable = 1;
        msg.paddr = paddr;
        _trusty_ioctl(SYSCALL_PLATFORM_FD_CSU, CSU_IOCMD_SECURE_DISP, &msg);

        /* This is a no-op in the case. */
        return SECURE_FB_ERROR_OK;
    }
};

static secure_fb_handle_t secure_fb_impl_init() {
    auto sfb = new SecureFbImpl();
    return sfb;
}

static int secure_fb_impl_get_fbs(secure_fb_handle_t sfb_handle,
                           struct secure_fb_impl_buffers* buffers) {
    SecureFbImpl* sfb = reinterpret_cast<SecureFbImpl*>(sfb_handle);
    sfb->Init(SECUREUI_WIDTH, SECUREUI_HEIGHT);
    return sfb->GetFbs(buffers);
}

static int secure_fb_impl_display_fb(secure_fb_handle_t sfb_handle,
                              uint32_t buffer_id) {
    SecureFbImpl* sfb = reinterpret_cast<SecureFbImpl*>(sfb_handle);
    return sfb->Display(buffer_id);
}

static int secure_fb_impl_release(secure_fb_handle_t sfb_handle) {
    SecureFbImpl* sfb = reinterpret_cast<SecureFbImpl*>(sfb_handle);
    delete sfb;
    return SECURE_FB_ERROR_OK;
}

static const struct secure_fb_impl_ops ops = {
    .init = secure_fb_impl_init,
    .get_fbs = secure_fb_impl_get_fbs,
    .display_fb = secure_fb_impl_display_fb,
    .release = secure_fb_impl_release,
};

int main(void) {
    int rc;
    struct tipc_hset* hset;

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("failed (%d) to create handle set\n", PTR_ERR(hset));
        return PTR_ERR(hset);
    }

    rc = add_secure_fb_service(hset, &ops, 1);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to initialize secure_fb service\n", rc);
        return rc;
    }

    return tipc_run_event_loop(hset);
}
