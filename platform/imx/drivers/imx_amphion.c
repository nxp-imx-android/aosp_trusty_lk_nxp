/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <lk/init.h>
#include <imx-regs.h>
#include <trace.h>
#include <reg.h>
#include <string.h>
#include <kernel/vm.h>
#include <kernel/physmem.h>
#include <lib/sm.h>
#include <lib/trusty/sys_fd.h>
#include <platform/imx_amphion.h>
#include <memcpy.h>

#define SMC_ENTITY_AMPHION 55
#define SMC_WV_PROBE SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 0)
#define SMC_WV_COPY SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 1)
#define SMC_WV_MEMSET SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 2)
#define SMC_WV_MESSAGE_BUFFER SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 3)
#define SMC_WV_HDR SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 4)
#define SMC_WV_CONTROL_VPU SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 5)
#define SMC_WV_CONTROL_VPU_CORE SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 6)
#define SMC_WV_MMAP_SAHRE_MEMORY SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 7)
#define SMC_WV_FIRMWARE_LOADED SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 8)
#define SMC_WV_GET_STATE SMC_FASTCALL_NR(SMC_ENTITY_AMPHION, 9)

#define PAGE_SZIE 4096
#define IMX8Q_CSR_CM0Px_CPUWAIT				0x00000004

static void* secure_stream_buffer = NULL;
static struct vpu_ctx vctx;

//secure heap phys_mem_obj
struct phys_mem_obj secure_heap_mem_obj;
struct obj_ref secure_heap_obj_self_ref;
void* secure_heap_base = NULL;

// firmware boot phys_mem_obj
struct phys_mem_obj firmware_boot_mem_obj;
struct obj_ref firmware_boot_obj_self_ref;
void* firmware_boot_base = NULL;
size_t firmware_boot_size;

static long amphion_probe(struct smc32_args* args) {
    /* check trusty amphion driver exist*/
    return 0;
}

/* secure memcpy */
static long amphion_copy(struct smc32_args* args) {
    struct vpu_fastcall_message* message = (struct vpu_fastcall_message*)vctx.message_buffer;
    uint32_t secure_memory_offset = message->secure_memory_offset;
    uint32_t dst_offset = message->dst_offset;
    uint32_t src_offset = message->src_offset;
    size_t size = message->size;
    paddr_t secure_dst_paddr = vaddr_to_paddr((uint8_t*)secure_stream_buffer + dst_offset);
    if(((secure_dst_paddr - SECURE_HEAP_BASE) >= SECURE_HEAP_SIZE) || ((secure_dst_paddr - SECURE_HEAP_BASE) < 0)) {
        return -1;
    }
    if (secure_memory_offset != 0x10000000) {
        memcpy_aarch64(secure_stream_buffer + dst_offset , secure_heap_base + secure_memory_offset + src_offset, size);
    } else {
        memcpy_aarch64(secure_stream_buffer + dst_offset, vctx.hdr_buffer + src_offset, size);
    }
    arch_clean_invalidate_cache_range((addr_t)(uint8_t*)secure_stream_buffer + dst_offset, size);
    return 0;
}

/* secure memset */
static long amphion_memset(struct smc32_args* args) {
    uint64_t offset = args->params[0];
    uint32_t value = args->params[1];
    size_t size = args->params[2];
    memset((uint8_t*)secure_stream_buffer + offset, value, size);
    return 0;
}

static void destroy_phys_mem(struct phys_mem_obj* obj) {
    return;
}

static long amphion_mmap_message_buffer(struct smc32_args* args) {
    if (args != NULL) {
        vctx.message_buffer_id = args->params[0] | ((uint64_t)args->params[1] << 32);;
        vctx.message_buffer_size = args->params[2];
        vctx.message_client_id = args->client_id;
    }
    size_t align_size = round_up(vctx.message_buffer_size, PAGE_SZIE);

    if (vctx.message_buffer == NULL) {
        int ret = ext_mem_map_obj_id(vmm_get_kernel_aspace(), "vpu-amphion",
                        vctx.message_client_id, vctx.message_buffer_id, 0,0,
                        align_size, &vctx.message_buffer, PAGE_SIZE_SHIFT, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
        if (ret) {
            printf("mmap messgae buffer failed ret:%d\n",ret);
            return ret;
        }
    }

    return 0;
}

static long amphion_mmap_hdr_buf(struct smc32_args* args) {
    if (args != NULL) {
        vctx.hdr_buffer_id = args->params[0] | ((uint64_t)args->params[1] << 32);
        vctx.hdr_buffer_size = args->params[2];
        vctx.hdr_client_id = args->client_id;
    }
    size_t align_size = round_up(vctx.hdr_buffer_size, PAGE_SZIE);

    if (vctx.hdr_buffer == NULL) {
        int ret = ext_mem_map_obj_id(vmm_get_kernel_aspace(), "vpu-amphion", vctx.hdr_client_id, vctx.hdr_buffer_id, 0,0,
                    align_size, &vctx.hdr_buffer, PAGE_SIZE_SHIFT, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
        if (ret) {
            printf("mmap hdr buffer failed ret:%d\n",ret);
            return ret;
        }
    }

    return 0;
}

static int mmap_secure_heap() {
    paddr_t secure_heap_paddr = SECURE_HEAP_BASE;
    size_t secure_heap_size = SECURE_HEAP_SIZE;
    int ret;
    /* mmap secure heap region */
    if (secure_heap_base == NULL) {
        phys_mem_obj_dynamic_initialize(&secure_heap_mem_obj,
                                    &secure_heap_obj_self_ref,
                                    secure_heap_paddr,
                                    secure_heap_size, ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_NO_EXECUTE,
                                    destroy_phys_mem);
        // mmap
        ret = vmm_alloc_obj(
            vmm_get_kernel_aspace(), "secure_heap", &secure_heap_mem_obj.vmm_obj,
            0, secure_heap_size, &secure_heap_base, 0, 0,
            ARCH_MMU_FLAG_PERM_NO_EXECUTE);
        if (ret) {
            printf("mmap secure heap failed ret:%d\n",ret);
            return ret;
        } else {
            secure_stream_buffer = secure_heap_base;
        }
    }

    return 0;

}

static int unmap_secure_heap() {
    int ret;
    /* free secure heap memory */
    ret = vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)secure_heap_base);
    if (ret)
        printf("secure heap free region failed ret=%d\n",ret);
    else
        secure_heap_base = NULL;

    /* free messgae share buffer */
    ret = vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)vctx.message_buffer);
    if (ret)
        printf("message_buffer free region failed ret=%d\n",ret);
    else
        vctx.message_buffer = NULL;

    /* free hdr share buffer */
    ret = vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)vctx.hdr_buffer);
    if (ret)
        printf("hdr_buffer free region failed ret=%d\n",ret);
    else
        vctx.hdr_buffer = NULL;

    return ret;
}

static int firmware_loaded(struct smc32_args* args) {
    *((uint8_t*)VPU_FIRMWARE_VIRT + 16) = args->params[0] | 0x80;
    *((uint8_t*)VPU_FIRMWARE_VIRT + 17) = args->params[1];
    *((uint8_t*)VPU_FIRMWARE_VIRT + 18) = args->params[2];

    return 0;
}

static u32 vpu_regs(struct smc32_args* args) {
    u32 reg = args->params[0];
    if (args->params[1] == 0x1) {
        return *REG32(VPU_REGS_BASE + reg);
    } else if (args->params[1] == 0x2) {
        *REG32(VPU_REGS_BASE + reg) = args->params[2];
        return 0;
    } else {
        return 0;
    }
}

static u32 vpu_core_regs(struct smc32_args* args) {
    u32 reg = args->params[0];
    if (args->params[1] == 0x1) {
        return *REG32(VPU_CORE_REGS_BASE + reg);
    } else if (args->params[1] == 0x2) {
        *REG32(VPU_CORE_REGS_BASE + reg) = args->params[2];
        return 0;
    } else {
        return 0;
    }
}

static int get_firmware_wfi_state() {
    return *((uint8_t*)VPU_FIRMWARE_VIRT + 19) == 1;
}

static int clear_boot_buffer() {
    for (u32 i =0; i < 0x800000; i++) {
        *((uint32_t*)VPU_FIRMWARE_VIRT + i) = 0;
    }
    return 0;
}

static int get_firmware_power_state() {
    int off = *REG32(VPU_CORE_REGS_BASE + IMX8Q_CSR_CM0Px_CPUWAIT);
    if (off)
        return 0;
    else
        return 1;
}

static long amphion_fastcall(struct smc32_args* args) {

    long ret = 0;
    if (args->smc_nr == SMC_WV_PROBE) {
        return amphion_probe(args);
    }

    if (args->smc_nr == SMC_WV_COPY) {
        return amphion_copy(args);
    }

    if (args->smc_nr == SMC_WV_MEMSET) {
        return amphion_memset(args);
    }

    if (args->smc_nr == SMC_WV_MESSAGE_BUFFER) {
        return amphion_mmap_message_buffer(args);
    }

    if (args->smc_nr == SMC_WV_HDR) {
        return amphion_mmap_hdr_buf(args);
    }

    if (args->smc_nr == SMC_WV_FIRMWARE_LOADED) {
        return firmware_loaded(args);
    }

    if (args->smc_nr == SMC_WV_CONTROL_VPU) {
        return vpu_regs(args);
    }

    if (args->smc_nr == SMC_WV_CONTROL_VPU_CORE) {
        return vpu_core_regs(args);
    }

    if (args->smc_nr == SMC_WV_MMAP_SAHRE_MEMORY) {
        if (args->params[0] == 1) {
            return mmap_secure_heap();
        } else {
            return unmap_secure_heap();
        }
    }

    if (args->smc_nr == SMC_WV_GET_STATE) {
        return get_firmware_wfi_state();
    }

    return ret;
}

static int32_t sys_amphion_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {
    switch (cmd) {
        case AMPHION_CLEAR_BOOT_BUFFER:
            return clear_boot_buffer();
        case AMPHION_GET_FIRMWARE_POWER:
            return get_firmware_power_state();
    }
    return 0;
}

static const struct sys_fd_ops amphion_ops = {
    .ioctl = sys_amphion_ioctl,
};

static struct smc32_entity amphion_entity = {
    .fastcall_handler = amphion_fastcall,
};

void amphion_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_AMPHION, &amphion_entity);
    vctx.message_buffer = NULL;
    vctx.hdr_buffer = NULL;
}

void platform_init_amphion(uint level) {
    install_sys_fd_handler(SYSCALL_PLATFORM_FD_AMPHION, &amphion_ops);
}


LK_INIT_HOOK(amphion_driver, amphion_smcall_init, LK_INIT_LEVEL_PLATFORM);
LK_INIT_HOOK(imx_amphion_ioctl, platform_init_amphion, LK_INIT_LEVEL_PLATFORM + 1);
