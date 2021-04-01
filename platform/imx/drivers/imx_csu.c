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
#include <reg.h>
#include <lib/sm/smcall.h>
#include <lib/sm.h>
#include <imx-regs.h>

#define LOCAL_TRACE     5

#define CSU_SA_OFFSET(id) (0x218 + (id/16)*4)
#define CSU_SA_SET(id) (1 << ((id % 16)*2))
#define CSU_CSL_OFFSET(id) ((id/2)*4)
#define CSU_CSL_SET(id,val) (val << ((id%2)*16))
#define CSU_CSL_CLEAN(id,val) (id%2 ? (val & 0x0000FFFF) : (val & 0xFFFF0000))

#define DRIVER_FD SYSCALL_PLATFORM_FD_CSU
#define CHECK_FD(x) \
        do { if(x!=DRIVER_FD) return ERR_BAD_HANDLE; } while (0)

#define PRINT_TRUSTY_APP_UUID(tid, u)                                          \
    LTRACEF("trusty_app %d uuid: 0x%x 0x%x 0x%x 0x%x%x 0x%x%x%x%x%x%x\n", tid, \
            (u)->time_low, (u)->time_mid, (u)->time_hi_and_version,            \
            (u)->clock_seq_and_node[0], (u)->clock_seq_and_node[1],            \
            (u)->clock_seq_and_node[2], (u)->clock_seq_and_node[3],            \
            (u)->clock_seq_and_node[4], (u)->clock_seq_and_node[5],            \
            (u)->clock_seq_and_node[6], (u)->clock_seq_and_node[7]);

static void *csu_base = (void*)CSU_BASE_VIRT;

static int32_t csu_cfg_csl(uint32_t cmd, user_addr_t user_ptr) {

    struct csu_cfg_csl_msg *msg = (struct csu_cfg_csl_msg*)user_ptr;
    uint32_t val = readl((uint8_t*)csu_base + CSU_CSL_OFFSET(msg->id));

    /* Clean and set the CSU CSL for LCDIF */
    val = CSU_CSL_CLEAN(msg->id, val);
    val |= CSU_CSL_SET(msg->id, msg->val);
    writel(val, (uint8_t*)csu_base + CSU_CSL_OFFSET(msg->id));

    return 0;
}

static int32_t csu_cfg_sa(uint32_t cmd, user_addr_t user_ptr) {
    struct csu_cfg_sa_msg *msg = (struct csu_cfg_sa_msg*) user_ptr;

    uint32_t val = readl((uint8_t*)csu_base + CSU_SA_OFFSET(msg->id));
    if (msg->enable) {
        val &= ~CSU_SA_SET(msg->id);
    } else {
        val |= CSU_SA_SET(msg->id);
    }
    writel(val, (uint8_t*)csu_base + CSU_SA_OFFSET(msg->id));

    return 0;
}

static int32_t sys_csu_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {
    struct trusty_app* app = current_trusty_app();
    PRINT_TRUSTY_APP_UUID(app->app_id, &app->props.uuid);
    CHECK_FD(fd);
    switch (cmd) {
        case CSU_IOCMD_STATUS:
            return CSU_OK;
        case CSU_IOCMD_CFG_SA:
            return csu_cfg_sa(cmd, user_ptr);
        case CSU_IOCMD_CFG_CSL:
            return csu_cfg_csl(cmd, user_ptr);
        case CSU_IOCMD_SECURE_DISP:
            return imx_secure_disp(cmd, user_ptr);
    }
    return CSU_OK;
}

static const struct sys_fd_ops csu_ops = {
    .ioctl = sys_csu_ioctl,
};

void platform_init_csu(uint level) {
    install_sys_fd_handler(SYSCALL_PLATFORM_FD_CSU, &csu_ops);
}

LK_INIT_HOOK(csu_dev_init, platform_init_csu, LK_INIT_LEVEL_PLATFORM + 1);
