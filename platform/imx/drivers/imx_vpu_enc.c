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
#include <trace.h>
#include <reg.h>

#define SMC_ENTITY_VPU_ENCODER 56
#define SMC_HANTROENC_PROBE SMC_FASTCALL_NR(SMC_ENTITY_VPU_ENCODER, 0)
#define SMC_VPU_ENC_REGS_OP SMC_FASTCALL_NR(SMC_ENTITY_VPU_ENCODER, 1)
#define SMC_CTRLBLK_REGS_OP SMC_FASTCALL_NR(SMC_ENTITY_VPU_ENCODER, 2)


#define SOCLE_LOGIC_0_BASE              (VPU_ENC_VIRT_BASE)
#define BLK_CTL_BASE                    (CTRLBLK_VIRT_BASE)
#define OPT_READ 0x1
#define OPT_WRITE 0x2
#define OPT1_READ 0x3
#define OPT1_WRITE 0x4

static long vpu_write_regs(uint32_t reg_index, uint32_t val) {
    *REG32(SOCLE_LOGIC_0_BASE + reg_index) = val;
    return 0;
}

static long vpu_read_regs(uint32_t reg_index) {
    return *REG32(SOCLE_LOGIC_0_BASE + reg_index);
}


static long ctrlblk_write_regs(uint32_t reg_index, uint32_t val) {
    *REG32(BLK_CTL_BASE + reg_index) = val;
    return 0;
}

static long ctrlblk_read_regs(uint32_t reg_index) {
    return *REG32(BLK_CTL_BASE + reg_index);
}

static long vpu_regs_op(struct smc32_args* args) {
    u32 target_index = args->params[0];
    u32 op = args->params[1];
    u32 val = args->params[2];

    if (op == OPT_READ) {
        return vpu_read_regs(target_index);
    }

    if (op == OPT_WRITE) {
        return vpu_write_regs(target_index, val);
    }

    return 0;
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

static long vpu_enc_fastcall(struct smc32_args* args) {
    if (args->smc_nr == SMC_VPU_ENC_REGS_OP) {
        return vpu_regs_op(args);
    }

    if (args->smc_nr == SMC_CTRLBLK_REGS_OP) {
        return ctrlblk_regs_op(args);
    }
    return 0;
}

static struct smc32_entity vpu_enc_entity = {
    .fastcall_handler = vpu_enc_fastcall,
};

void vpu_enc_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_VPU_ENCODER, &vpu_enc_entity);
}

LK_INIT_HOOK(vpu_enc_driver, vpu_enc_smcall_init, LK_INIT_LEVEL_PLATFORM);

