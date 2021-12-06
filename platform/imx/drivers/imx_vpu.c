/*
* Copyright 2021 NXP.
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
#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <lk/init.h>
#include <imx-regs.h>
#include <imx_rdc.h>
#include <trace.h>
#include <reg.h>

#define SMC_ENTITY_VPU 55
#define SMC_HANTRO_PROBE SMC_FASTCALL_NR(SMC_ENTITY_VPU, 0)
#define SMC_VPU_REGS_OP SMC_FASTCALL_NR(SMC_ENTITY_VPU, 1)
#define SMC_CTRLBLK_REGS_OP SMC_FASTCALL_NR(SMC_ENTITY_VPU, 2)

#define SOCLE_LOGIC_0_BASE              (VPUG1_VIRT_BASE)
#define SOCLE_LOGIC_1_BASE              (VPUG2_VIRT_BASE)
#define BLK_CTL_BASE                    (CTRLBLK_VIRT_BASE) //0x38320000

#define OPT_READ  0x1
#define OPT_WRITE 0x2
#define OPT_SECURE_WRITE 0x3
#define OPT_SECURE_CTRL_WRITE 0x4
#define OPT_SECURE_PPCTRL_WRITE 0x5

#define UNMAPPED_HEAP_ADDR   0xE0000000
#define UNMAPPED_HEAP_SIZE   0x10000000

#define G2_SECURE_REGS_SIZE 5
#define RDC_MDAn(n) (RDC_BASE_VIRT + 0x200 + (n * 4))
#define DID0 (0x0)
#define DID1 (0x1)
#define DID2 (0x2)
#define DID3 (0x3)
static uint32_t inout_buffer_paddr[2][2] = {{12 * 4, 0x0}, {13 * 4, 0x0}};
static uint32_t inout_buffer_g2_paddr[G2_SECURE_REGS_SIZE][2] = {{169 * 4, 0x0}, /* input buffer  */
                                               {175 * 4, 0x0}, /* output buffer HWIF_DEC_DSY_BASE_LSB */
                                               {186 * 4, 0x0}, /* HWIF_DEC_DSY_BASE_LSB ,downscale not used*/
                                               {65 * 4 , 0x0}, /* HWIF_DEC_OUT_YBASE_LSB, pp refrence outbuffer for nv12*/
                                               {190 * 4, 0x0}  /* HWIF_DEC_OUT_TYBASE_LSB, pp refrence outbuffer for DTRC not used by android */};

int set_widevine_vpu_secure_mode(bool enable, uint32_t vpu_type) {
    if (enable) {
        writel(DID2, RDC_MDAn(vpu_type));
    } else {
        writel(DID0, RDC_MDAn(vpu_type));
    }
    return 0;
}

bool is_unmapped_heap(uint64_t paddr) {
    if (paddr >= UNMAPPED_HEAP_ADDR && paddr < (UNMAPPED_HEAP_ADDR + UNMAPPED_HEAP_SIZE)) {
        return true;
    } else if (paddr == 0) {
        return true;
    } else {
        return false;
    }
}
uint8_t in_out_addr_align(uint32_t (*paddr)[2], size_t rows) {
    uint8_t ret = 0b00000000;
    for (size_t i = 0; i < rows; i++) {
        if (is_unmapped_heap(paddr[i][1]))
            ret = ret | (1 << i);
    }
    return ret;
}

static bool check_secure_regs(uint32_t reg_index, uint64_t regs_base) {
    if ((regs_base == SOCLE_LOGIC_0_BASE) && (reg_index == inout_buffer_paddr[0][0] || reg_index == inout_buffer_paddr[1][0]))
        return true;
    if ((regs_base == SOCLE_LOGIC_1_BASE) && (reg_index == inout_buffer_g2_paddr[0][0] || reg_index == inout_buffer_g2_paddr[1][0]
                || reg_index == inout_buffer_g2_paddr[2][0] || reg_index == inout_buffer_g2_paddr[3][0] || reg_index == inout_buffer_g2_paddr[4][0]))
        return true;
    return false;
}
static bool check_regs_range(uint32_t reg_index, uint64_t regs_base) {
    if ((regs_base == SOCLE_LOGIC_0_BASE) && (reg_index < DEC_IO_SIZE_0 && reg_index >= 0))
        return true;
    else if ((regs_base == SOCLE_LOGIC_1_BASE) && (reg_index < DEC_IO_SIZE_1 && reg_index >= 0))
        return true;
    else if ((regs_base == BLK_CTL_BASE) && (reg_index < CTRLBLK_VIRT_SIZE && reg_index >= 0))
        return true;
    return false;
}

static long vpu_secure_write_regs(uint32_t reg_index, uint32_t val, u32 option) {
    if ((option & 0xf0) >> 4 == 0) {
        if (reg_index == inout_buffer_paddr[0][0])
            inout_buffer_paddr[0][1] = val;
        else if (reg_index == inout_buffer_paddr[1][0])
            inout_buffer_paddr[1][1] = val;
        else
            return -1;
    } else if ((option & 0xf0) >> 4 == 1) {
        if (reg_index == inout_buffer_g2_paddr[0][0])
            inout_buffer_g2_paddr[0][1] = val;
        else if(reg_index == inout_buffer_g2_paddr[1][0])
            inout_buffer_g2_paddr[1][1] = val;
        else if(reg_index == inout_buffer_g2_paddr[2][0])
            inout_buffer_g2_paddr[2][1] = val;
        else if(reg_index == inout_buffer_g2_paddr[3][0])
            inout_buffer_g2_paddr[3][1] = val;
        else if (reg_index == inout_buffer_g2_paddr[4][0])
            inout_buffer_g2_paddr[4][1] = val;
        else
            return -1;
    }
    return 0;
}

static long vpu_write_regs(uint32_t reg_index, uint32_t val, u32 option) {
    uint64_t regs_viraddr_base = ((option & 0xf0) >> 4) == 0 ? SOCLE_LOGIC_0_BASE: SOCLE_LOGIC_1_BASE;
    if(check_regs_range(reg_index, regs_viraddr_base)) {
        if (check_secure_regs(reg_index, regs_viraddr_base))
            vpu_secure_write_regs(reg_index, val, option);
        else
            *REG32(regs_viraddr_base + reg_index) = val;
    } else {
        return -1;
    }
    return 0;
}

static long vpu_read_regs(uint32_t reg_index, u32 option) {
    uint64_t regs_viraddr_base = ((option & 0xf0) >> 4) == 0 ? SOCLE_LOGIC_0_BASE: SOCLE_LOGIC_1_BASE;
    if(check_regs_range(reg_index, regs_viraddr_base))
        return *REG32(regs_viraddr_base + reg_index);
    else
        return -1;
}

static long vpu_g2_read_regs(uint32_t reg_index) {
    if(check_regs_range(reg_index, SOCLE_LOGIC_1_BASE))
        return *REG32(SOCLE_LOGIC_1_BASE + reg_index);
    else
        return -1;
}

static long ctrlblk_write_regs(uint32_t reg_index, uint32_t val) {
    if(check_regs_range(reg_index, BLK_CTL_BASE))
        *REG32(BLK_CTL_BASE + reg_index) = val;
    else
        return -1;
    return 0;
}

static long ctrlblk_read_regs(uint32_t reg_index) {
    if(check_regs_range(reg_index, BLK_CTL_BASE))
        return *REG32(BLK_CTL_BASE + reg_index);
    else
        return -1;
}

static long vpu_secure_ctrl_regs(uint32_t reg_index, uint32_t val, u32 option) {
    uint32_t (*buffer_paddr_array)[2], vpu_rdc_addr;
    size_t buffer_paddr_array_size;
    uint8_t align_flags;
    uint64_t regs_viraddr_base ;
    if ((option & 0xf0) >> 4 == 0) {
        buffer_paddr_array = inout_buffer_paddr;
        buffer_paddr_array_size = 2;
        align_flags = 0x3;
        regs_viraddr_base = SOCLE_LOGIC_0_BASE;
#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM)
        vpu_rdc_addr = RDC_MDA_VPUG1;
#elif defined(MACH_IMX8MQ)
        vpu_rdc_addr = RDC_MDA_VPU_DEC;
#endif
    } else if ((option & 0xf0) >> 4 == 1) {
        buffer_paddr_array = inout_buffer_g2_paddr;
        buffer_paddr_array_size = G2_SECURE_REGS_SIZE;
        align_flags = 0b11111;
        regs_viraddr_base = SOCLE_LOGIC_1_BASE;
#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM)
        vpu_rdc_addr = RDC_MDA_VPUG2;
#elif defined(MACH_IMX8MQ)
        vpu_rdc_addr = RDC_MDA_VPU_DEC;
#endif
    }
    if (val & 0x1) {
        uint8_t is_align = in_out_addr_align(buffer_paddr_array, buffer_paddr_array_size);
        if (is_align == 0x0 || is_align == align_flags) {
            for (size_t i = 0; i < buffer_paddr_array_size; i++) {
                *REG32(regs_viraddr_base + buffer_paddr_array[i][0]) = buffer_paddr_array[i][1];
            }
            if (is_align == align_flags)
                set_widevine_vpu_secure_mode(true, vpu_rdc_addr);
            else
                set_widevine_vpu_secure_mode(false, vpu_rdc_addr);
        } else {
            return -1;
        }
    }
    return vpu_write_regs(reg_index, val, option);
}

static long vpu_secure_ppctrl_regs(uint32_t reg_index, uint32_t val, u32 option) {

    uint8_t is_align = in_out_addr_align(inout_buffer_g2_paddr, G2_SECURE_REGS_SIZE);
    if (is_align == 0x0 || is_align == 0b1011) {
         *REG32(SOCLE_LOGIC_1_BASE + inout_buffer_g2_paddr[3][0]) = inout_buffer_g2_paddr[3][1];
    } else {
        return -1;
    }
    return vpu_write_regs(reg_index, val, option);
}

static long vpu_regs_op(struct smc32_args* args) {
    u32 target_index = args->params[0];
    u32 op = args->params[1] & 0x0f;
    u32 option = args->params[1];
    u32 val = args->params[2];
    switch (op) {
        case OPT_READ:
            return vpu_read_regs(target_index, option);
        case OPT_WRITE:
            return vpu_write_regs(target_index, val, option);
        case OPT_SECURE_WRITE:
            return vpu_secure_write_regs(target_index, val, option);
        case OPT_SECURE_CTRL_WRITE:
            return vpu_secure_ctrl_regs(target_index, val, option);
        case OPT_SECURE_PPCTRL_WRITE:
            return vpu_secure_ppctrl_regs(target_index, val, option);
        default:
            return 0;
    }
}


static long ctrlblk_regs_op(struct smc32_args* args) {
    u32 target_index = args->params[0];
    u32 op = args->params[1];
    u32 val = args->params[2];

    if (op == OPT_READ) {
        return ctrlblk_read_regs(target_index);
    }

    if (op == OPT_WRITE) {
        return ctrlblk_write_regs(target_index, val);
    }
    return 0;
}

static long vpu_fastcall(struct smc32_args* args) {

    if (args->smc_nr == SMC_VPU_REGS_OP) {
        return vpu_regs_op(args);
    }

    if (args->smc_nr == SMC_CTRLBLK_REGS_OP) {
        return ctrlblk_regs_op(args);
    }

    return 0;
}

static struct smc32_entity vpu_entity = {
    .fastcall_handler = vpu_fastcall,
};

void vpu_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_VPU, &vpu_entity);
}

LK_INIT_HOOK(vpu_driver, vpu_smcall_init, LK_INIT_LEVEL_PLATFORM);

