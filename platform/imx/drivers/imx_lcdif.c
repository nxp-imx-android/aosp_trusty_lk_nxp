/*
 * Copyright 2023 NXP
 *
 */

#include <debug.h>
#include <err.h>
#include <kernel/vm.h>
#include <lib/trusty/sys_fd.h>
#include <lib/trusty/trusty_app.h>
#include <lk/init.h>
#include <mm.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <platform/imx_csu.h>
#include <platform/imx_lcdif.h>
#include <platform/lcdif-regs.h>
#include <platform/lcdifv3-regs.h>
#include <imx-regs.h>
#include <reg.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>

#define LOCAL_TRACE     5

#define SMC_ENTITY_IMX_LINUX_OPT 54
#define SMC_IMX_ECHO SMC_FASTCALL_NR(SMC_ENTITY_IMX_LINUX_OPT, 0)
#define SMC_IMX_LCDIF_ADDR SMC_FASTCALL_NR(SMC_ENTITY_IMX_LINUX_OPT, 1)
#define SMC_IMX_LCDIF_REG  SMC_FASTCALL_NR(SMC_ENTITY_IMX_LINUX_OPT, 2)
#define OPT_WRITE 0x2

static bool tee_ctrl_lcdif = false;
static uint32_t last_linux_fb_addr = 0x00000000;
static uint32_t last_tee_fb_addr = 0x0;

static void wait_for_lcdif_irq() {
    uint32_t timeout = 0x0000FFFF;
    uint32_t val;

    while (timeout) {
        timeout--;
#ifdef MACH_IMX8MP
        val = readl((uint8_t*)LCDIFV3_BASE_VIRT + LCDIFV3_INT_STATUS_D0);
        if (val & (1 << 2)) {
#else
        val = readl((uint8_t*)LCDIF_BASE_VIRT + LCDIF_CTRL1);
        if (val & (1 << 9)) {
#endif
            return;
        }
    }
}

int32_t imx_secure_disp(uint32_t cmd, user_addr_t user_ptr) {
    struct csu_cfg_secure_disp_msg *msg = (struct csu_cfg_secure_disp_msg*) user_ptr;
    if (msg->enable) {
        tee_ctrl_lcdif = true;
        wait_for_lcdif_irq();
        last_tee_fb_addr = msg->paddr;
#ifdef MACH_IMX8MP
        writel(last_tee_fb_addr, (uint8_t*)LCDIFV3_BASE_VIRT + LCDIFV3_CTRLDESCL_LOW0_4);
#else
        writel(last_tee_fb_addr, (uint8_t*)LCDIF_BASE_VIRT + LCDIF_NEXT_BUF);
#endif
    } else {
        wait_for_lcdif_irq();
#ifdef MACH_IMX8MP
        writel(last_linux_fb_addr, (uint8_t*)LCDIFV3_BASE_VIRT + LCDIFV3_CTRLDESCL_LOW0_4);
#else
        writel(last_linux_fb_addr, (uint8_t*)LCDIF_BASE_VIRT + LCDIF_NEXT_BUF);
#endif
        tee_ctrl_lcdif = false;
    }

#ifdef MACH_IMX8MP
    /* enable shadow load */
    uint32_t ctrldescl0_5 = readl((uint8_t*)LCDIFV3_BASE_VIRT + LCDIFV3_CTRLDESCL0_5);
    ctrldescl0_5 |= (1UL << 30);
    writel(ctrldescl0_5, (uint8_t*)LCDIFV3_BASE_VIRT + LCDIFV3_CTRLDESCL0_5);
#endif

    return 0;
}

static long imx_linux_lcdif_reg(struct smc32_args* args) {
    u32 target = args->params[0];
    u32 op = args->params[1];
    u32 val = args->params[2];
    if (op == OPT_WRITE) {
        switch (target) {
#ifdef MACH_IMX8MP
            case LCDIFV3_PANIC0_THRES:
            case LCDIFV3_INT_ENABLE_D1:
            case LCDIFV3_INT_STATUS_D0:
            case LCDIFV3_INT_ENABLE_D0:
            case LCDIFV3_CTRLDESCL0_5:
            case LCDIFV3_DISP_PARA:
            case LCDIFV3_CTRLDESCL0_3:
            case LCDIFV3_DISP_SIZE:
            case LCDIFV3_HSYN_PARA:
            case LCDIFV3_VSYN_PARA:
            case LCDIFV3_VSYN_HSYN_WIDTH:
            case LCDIFV3_CTRLDESCL0_1:
            case LCDIFV3_CTRL_SET:
            case LCDIFV3_CTRL_CLR:
                writel(val, (uint8_t*)LCDIFV3_BASE_VIRT + target);
                return 0;
            case LCDIFV3_CTRLDESCL_LOW0_4:
                last_linux_fb_addr = val;
                if (tee_ctrl_lcdif)
                    writel(last_tee_fb_addr, (uint8_t*)LCDIFV3_BASE_VIRT + target);
                else
                    writel(val, (uint8_t*)LCDIFV3_BASE_VIRT + target);
                return 0;
#else
            case LCDIF_CTRL:
            case LCDIF_CTRL1:
            case LCDIF_CTRL2:
            case LCDIF_CTRL + REG_CLR:
            case LCDIF_CTRL + REG_SET:
            case LCDIF_CTRL1 + REG_CLR:
            case LCDIF_CTRL1 + REG_SET:
            case LCDIF_CTRL2 + REG_CLR:
            case LCDIF_CTRL2 + REG_SET:
            case HW_EPDC_PIGEON_12_0:
            case HW_EPDC_PIGEON_12_1:
            case HW_EPDC_PIGEON_12_2:
            case LCDIF_TRANSFER_COUNT:
            case LCDIF_VDCTRL0:
            case LCDIF_VDCTRL1:
            case LCDIF_VDCTRL2:
            case LCDIF_VDCTRL3:
            case LCDIF_VDCTRL4:
                writel(val, (uint8_t*)LCDIF_BASE_VIRT + target);
                return 0;
            case LCDIF_NEXT_BUF:
                last_linux_fb_addr = val;
                if (tee_ctrl_lcdif)
                    writel(last_tee_fb_addr, (uint8_t*)LCDIF_BASE_VIRT + target);
                else
                    writel(val, (uint8_t*)LCDIF_BASE_VIRT + target);
                return 0;
#endif
            default:
                LTRACEF("imx_linux_lcdif_reg wrong target for 0x%x\n", target);
        }
    }
    return -1;
}

static long imx_linux_fastcall(struct smc32_args* args) {
    switch (args->smc_nr) {
        case SMC_IMX_ECHO:
            return 0;
        case SMC_IMX_LCDIF_REG:
            return imx_linux_lcdif_reg(args);

    }
    return 0;
}

static struct smc32_entity imx_linux_entity = {
    .fastcall_handler = imx_linux_fastcall,
};

void imx_linux_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_IMX_LINUX_OPT, &imx_linux_entity);
}

LK_INIT_HOOK(imx_linux_driver, imx_linux_smcall_init, LK_INIT_LEVEL_PLATFORM);
