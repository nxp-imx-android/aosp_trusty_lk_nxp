#include <lib/tipc/tipc.h>
#include <lib/syscall.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <stdio.h>
#include <lk/err_ptr.h>
#include <lk/reg.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <interface/hwsecure/hwsecure.h>
#include "hwsecure.h"
#include "imx-regs.h"

#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM) || defined (MACH_IMX8MQ)
#include <platform/imx_csu.h>
#include "nxp_memmap_consts.h"
#ifdef MACH_IMX8MP
#include <imx_rdc.h>
#endif
#elif defined (MACH_IMX8ULP)
#include <platform/imx_xrdc.h>
#endif

#define TLOG_TAG "hwsecure"

extern "C" long _trusty_ioctl(uint32_t fd, uint32_t req, void *buf);

#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM) || defined (MACH_IMX8MQ)
static void *csu_base = NULL;
static uint8_t* rdc_base = NULL;
#ifdef MACH_IMX8MP
static g2d_secure_mode current_g2d_secure_mode = NON_SECURE;
#endif
#define RDC_MDAn(n) (rdc_base + 0x200 + (n * 4))
#define DID0 (0x0)
#define DID1 (0x1)
#define DID2 (0x2)
#define DID3 (0x3)


int init_csu(void) {
    csu_base = mmap(NULL, CSU_REG_SIZE, PROT_READ | PROT_WRITE,
            MMAP_FLAG_IO_HANDLE, CSU_MMIO_ID, 0);

    if (csu_base == MAP_FAILED) {
        TLOGE("init_csu failed due map failed!\n");
        return ERR_GENERIC;
    }

    return 0;
}

int init_rdc(void) {
    rdc_base = (uint8_t*)mmap(NULL, RDC_REG_SIZE, PROT_READ | PROT_WRITE,
            MMAP_FLAG_IO_HANDLE, RDC_MMIO_ID, 0);

    if (rdc_base == MAP_FAILED) {
        TLOGE("init_rdc failed due map failed!\n");
        return ERR_GENERIC;
    }

    return 0;
}
#endif

#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM)
static int set_lcdif_secure_sa(uint32_t enable) {
    int ret;
    struct csu_cfg_sa_msg sa_msg;
    sa_msg.id = CSU_SA_LCDIF_ID;
    sa_msg.enable = enable;
    ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_CSU, CSU_IOCMD_CFG_SA, &sa_msg);
    if (ret != CSU_OK) {
        TLOGE("csu ioctl failed. cmd=%d\n", CSU_IOCMD_CFG_SA);
        return ret;
    }
    return 0;
}

static int set_lcdif_secure_csl(uint32_t csl_val) {
    int ret;
    struct csu_cfg_csl_msg csl_msg;
    csl_msg.id = CSU_CSL_LCDIF_ID;
    csl_msg.val = csl_val;

    ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_CSU, CSU_IOCMD_CFG_CSL, &csl_msg);
    if (ret != CSU_OK) {
        TLOGE("csu ioctl failed. cmd=%d\n", CSU_IOCMD_CFG_CSL);
        return ret;
    }
    return 0;
}
#elif defined(MACH_IMX8MQ)
static int set_dcss_secure_csl(uint32_t csl_val) {
    int ret;
    struct csu_cfg_csl_msg csl_msg;
    int DCSS_CSL_ID[4] = {CSU_CSL_MST0_ID, CSU_CSL_MST1_ID, CSU_CSL_MST2_ID, CSU_CSL_MST3_ID};
    for (size_t i = 0; i < 4; i++ ) {
        csl_msg.id = DCSS_CSL_ID[i];
        csl_msg.val = csl_val;
        ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_CSU, CSU_IOCMD_CFG_CSL, &csl_msg);
        if (ret != CSU_OK) {
            TLOGE("csu ioctl failed. cmd=%d\n", CSU_IOCMD_CFG_CSL);
            return ret;
        }
    }
    return 0;
}
#endif

int set_widevine_g2d_secure_mode(uint32_t cmd) {

#ifdef MACH_IMX8MP
    if (cmd == HWSECURE_WV_G2D_SECURE) {
        writel(DID2, RDC_MDAn(RDC_MDA_GPU2D));
        current_g2d_secure_mode = SECURE;
    } else if (cmd == HWSECURE_WV_G2D_NON_SECURE) {
        writel(DID0, RDC_MDAn(RDC_MDA_GPU2D));
        current_g2d_secure_mode = NON_SECURE;
    } else {
        return ERR_INVALID_ARGS;
    }
    return 0;
#else
    return ERR_GENERIC;
#endif

}

int get_widevine_g2d_secure_mode(int &mode) {
#ifdef MACH_IMX8MP
    mode =(int)current_g2d_secure_mode;
    return 0;
#else
    return ERR_GENERIC;
#endif
}

#if defined(MACH_IMX8MP) || defined(MACH_IMX8MM)
int set_lcdif_secure(uint32_t cmd) {
    if (cmd == HWSECURE_LCDIF_SECURE_ACCESS) {
       if (set_lcdif_secure_csl(CSL_SECURE_ONLY)) {
           return ERR_GENERIC;
       }
       if (set_lcdif_secure_sa(1)) {
           return ERR_GENERIC;
       }
    } else if (cmd == HWSECURE_LCDIF_NON_SECURE_ACCESS) {
       if (set_lcdif_secure_sa(0)) {
           return ERR_GENERIC;
       }
       if (set_lcdif_secure_csl(CSL_DEFAULT)) {
           return ERR_GENERIC;
       }
    } else {
        return ERR_INVALID_ARGS;
    }

    return 0;
}
#elif defined(MACH_IMX8MQ)
int set_dcss_secure(uint32_t cmd) {
    if (cmd == HWSECURE_DCSS_SECURE_ACCESS) {
       if (set_dcss_secure_csl(CSL_SECURE_ONLY)) {
           return ERR_GENERIC;
       }
    } else if (cmd == HWSECURE_DCSS_NON_SECURE_ACCESS) {
       if (set_dcss_secure_csl(CSL_DEFAULT)) {
           return ERR_GENERIC;
       }
    } else {
        return ERR_INVALID_ARGS;
    }

    return 0;

}
#elif defined(MACH_IMX8ULP)
int set_dcnano_secure(uint32_t cmd) {
    if (cmd == HWSECURE_DCNANO_SECURE_ACCESS) {
        int ret = 0;
        /* set DCnano can access secure memory as master */
        struct xrdc_mda_config dcnano_mda = {13, 3, MDA_SA_S};
        /* set DCnano can be read/write by Secure User/Priv
         * but can only be read by Non-Secure User/Priv
         */
	struct xrdc_pac_msc_config dcnano_msc = { 2, 5, {0, 0, 0, 0, 0, 0, 5, 5} };

        ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_XRDC, XRDC_IOCMD_CFG_MDA, &dcnano_mda);
        if (ret) {
            TLOGE("xrdc ioctl failed. cmd=%d\n", XRDC_IOCMD_CFG_MDA);
            return ret;
         }

        ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_XRDC, XRDC_IOCMD_CFG_MSC, &dcnano_msc);
        if (ret) {
            TLOGE("xrdc ioctl failed. cmd=%d\n", XRDC_IOCMD_CFG_MSC);
            return ret;
         }

    } else if (cmd == HWSECURE_DCNANO_NON_SECURE_ACCESS) {
        int ret = 0;
        /* set DCnano can only access normal memory as master */
        struct xrdc_mda_config dcnano_mda = {13, 3, MDA_SA_NS};
        /* set DCnano can be read/write by Secure/Non-secure User/Priv */
        struct xrdc_pac_msc_config dcnano_msc = { 2, 5, {0, 0, 0, 0, 0, 0, 7, 7} };

        ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_XRDC, XRDC_IOCMD_CFG_MDA, &dcnano_mda);
        if (ret) {
            TLOGE("xrdc ioctl failed. cmd=%d\n", XRDC_IOCMD_CFG_MDA);
            return ret;
         }

        ret = _trusty_ioctl(SYSCALL_PLATFORM_FD_XRDC, XRDC_IOCMD_CFG_MSC, &dcnano_msc);
        if (ret) {
            TLOGE("xrdc ioctl failed. cmd=%d\n", XRDC_IOCMD_CFG_MSC);
            return ret;
         }
    }
    return 0;
}
#endif

