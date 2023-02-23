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
#include <platform/imx_dcnano.h>
#include <platform/dcnano-regs.h>
#include <imx-regs.h>
#include <reg.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>

#define DRIVER_FD SYSCALL_PLATFORM_FD_DCNANO
#define CHECK_FD(x) \
                do { if(x!=DRIVER_FD) return ERR_BAD_HANDLE; } while (0)


#define SMC_ENTITY_IMX_LINUX_OPT 54
#define SMC_IMX_ECHO SMC_FASTCALL_NR(SMC_ENTITY_IMX_LINUX_OPT, 0)
#define SMC_IMX_DCNANO_REG  SMC_FASTCALL_NR(SMC_ENTITY_IMX_LINUX_OPT, 1)
#define OPT_WRITE 0x2

#define ALIGN(x,y) (((x)+(y-1))&~(y-1))

#define LOCAL_TRACE     5

static bool tee_ctrl_dcnano = false;
static uint32_t last_linux_fb_addr = 0x00000000;
static uint32_t last_linux_fb_picture = 0x0;
static uint32_t last_tee_fb_addr = 0x0;
static uint32_t last_tee_fb_picture = 0x0;

static void wait_for_dcnano_irq() {
    uint32_t timeout = 0x00FFFFFF;
    uint32_t val;

    while (timeout) {
        timeout--;
        val = readl((uint8_t*)DCNANO_BASE_VIRT + DCNANO_DISPLAYINTR);
        if ((val & 0x00000001) == 1) {
            return;
        }
    }
}


static int32_t imx_dcnano_secure_disp(uint32_t cmd, user_addr_t user_ptr) {
    struct csu_cfg_secure_disp_msg *msg = (struct csu_cfg_secure_disp_msg*) user_ptr;
    if (msg->enable) {
        tee_ctrl_dcnano = true;
        wait_for_dcnano_irq();
        last_tee_fb_addr = msg->paddr;
        last_tee_fb_picture = ALIGN(720*4, DCNANO_FB_PITCH_ALIGN);
        writel(last_tee_fb_addr, (uint8_t*)DCNANO_BASE_VIRT + DCNANO_FRAMEBUFFERADDRESS);
        writel(last_tee_fb_picture, (uint8_t*)DCNANO_BASE_VIRT + DCNANO_FRAMEBUFFERSTRIDE);
    } else {
        wait_for_dcnano_irq();
        writel(last_linux_fb_addr, (uint8_t*)DCNANO_BASE_VIRT + DCNANO_FRAMEBUFFERADDRESS);
        writel(last_linux_fb_picture, (uint8_t*)DCNANO_BASE_VIRT + DCNANO_FRAMEBUFFERSTRIDE);
        tee_ctrl_dcnano = false;
    }

    return 0;
}

static long imx_linux_dcnano_reg(struct smc32_args* args) {
    u32 target = args->params[0];
    u32 op = args->params[1];
    u32 val = args->params[2];
    if (op == OPT_WRITE) {
        switch (target) {
            case DCNANO_FRAMEBUFFERCONFIG:
            case DCNANO_DISPLAYDITHERCONFIG:
            case DCNANO_DISPLAYDITHERTABLELOW:
            case DCNANO_DISPLAYDITHERTABLEHIGH:
            case DCNANO_PANELCONFIG:
            case DCNANO_PANELTIMING:
            case DCNANO_HDISPLAY:
            case DCNANO_HSYNC:
            case DCNANO_VDISPLAY:
            case DCNANO_VSYNC:
            case DCNANO_DISPLAYCURRENTLOCATION:
            case DCNANO_GAMMAINDEX:
            case DCNANO_GAMMADATA:
            case DCNANO_CURSORCONFIG:
            case DCNANO_CURSORLOCATION:
            case DCNANO_CURSORBACKGROUND:
            case DCNANO_CURSORFOREGROUND:
            case DCNANO_DISPLAYINTR:
            case DCNANO_DISPLAYINTRENABLE:
            case DCNANO_DBICONFIG:
            case DCNANO_DBIIFRESET:
            case DCNANO_DBIWRCHAR1:
            case DCNANO_DBIWRCHAR2:
            case DCNANO_DBICMD:
            case DCNANO_DPICONFIG:
            case DCNANO_DCCHIPREV:
            case DCNANO_DCCHIPDATE:
            case DCNANO_DCCHIPPATCHREV:
            case DCNANO_DCTILEINCFG:
            case DCNANO_DCTILEUVFRAMEBUFFERSTR:
            case DCNANO_DCPRODUCTID:
            case DCNANO_DCSTATUS:
            case DCNANO_DEBUGCOUNTERSELECT:
            case DCNANO_DEBUGCOUNTERVALUE:
                writel(val, (uint8_t*)DCNANO_BASE_VIRT + target);
                return 0;
            case DCNANO_CURSORADDRESS:
            case DCNANO_DCTILEUVFRAMEBUFFERADR:
                /*need to judge whether the addr is not trusty memory*/
                if ((val >= MEMBASE) && (val < MEMBASE + MEMSIZE))
                    return 0;
                writel(val, (uint8_t*)DCNANO_BASE_VIRT + target);
                return 0;
            case DCNANO_FRAMEBUFFERADDRESS:
                last_linux_fb_addr = val;
                if (tee_ctrl_dcnano) {
                    writel(last_tee_fb_addr, (uint8_t*)DCNANO_BASE_VIRT + target);
                } else {
                    writel(val, (uint8_t*)DCNANO_BASE_VIRT + target);
                }
                return 0;
            case DCNANO_FRAMEBUFFERSTRIDE:
                last_linux_fb_picture = val;
                if (tee_ctrl_dcnano)
                    writel(last_tee_fb_picture, (uint8_t*)DCNANO_BASE_VIRT + target);
                else
                    writel(val, (uint8_t*)DCNANO_BASE_VIRT + target);
                return 0;
            default:
                LTRACEF("imx_linux_dcnano_reg wrong target for 0x%x\n", target);
        }
    }
    return -1;
}


static long imx_linux_fastcall(struct smc32_args* args) {
    switch (args->smc_nr) {
        case SMC_IMX_ECHO:
            return 0;
        case SMC_IMX_DCNANO_REG:
            return imx_linux_dcnano_reg(args);

    }
    return 0;
}

static int32_t sys_dcnano_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {
    CHECK_FD(fd);
    switch (cmd) {
        case CSU_IOCMD_SECURE_DISP:
            return imx_dcnano_secure_disp(cmd, user_ptr);
    }
    return 0;
}


static struct smc32_entity imx_linux_dcnano_entity = {
    .fastcall_handler = imx_linux_fastcall,
};

static const struct sys_fd_ops dcnano_ops = {
    .ioctl = sys_dcnano_ioctl,
};

void imx_linux_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_IMX_LINUX_OPT, &imx_linux_dcnano_entity);
}

void platform_init_dcnano(uint level) {
    install_sys_fd_handler(SYSCALL_PLATFORM_FD_DCNANO, &dcnano_ops);
}

LK_INIT_HOOK(sys_dcnano_ioctl, platform_init_dcnano, LK_INIT_LEVEL_PLATFORM + 1);
LK_INIT_HOOK(imx_linux_dcnano_driver, imx_linux_smcall_init, LK_INIT_LEVEL_PLATFORM);



