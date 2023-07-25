/*
 * Copyright 2023 NXP
 *
 */

#include <dev/uart.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <sci/rpc.h>
#include <imx-regs.h>
#include <sci/svc/misc/api.h>
#include <platform/imx_scu.h>
#include <lib/trusty/sys_fd.h>
#include <lk/init.h>
#include <sci/types.h>
#include <lib/sm.h>
#include <lib/sm/smc.h>
#include <lib/sm/smcall.h>
#include <sci/svc/pm/api.h>
#include <platform/imx_sip.h>

#define SMC_ENTITY_SCU 56
#define SMC_SCU_MISC_CONTROL SMC_FASTCALL_NR(SMC_ENTITY_SCU, 0)
#define SMC_WV_POWER_SET SMC_FASTCALL_NR(SMC_ENTITY_SCU, 1)
#define SMC_WV_DPU_POWER_SET SMC_FASTCALL_NR(SMC_ENTITY_SCU, 2)

#define RES_OWNED_BY_LINUX (-100)

sc_rm_pt_t vpu_part, os_part;
sc_rm_pt_t dpu_part = 7;
sc_rm_pt_t secure_part;

sc_rsrc_t secure_wr_access_allowed[] = {
    SC_R_VPU,
    SC_R_VPU_DEC_0,
};

sc_rsrc_t ns_access_allowed[] = {
    SC_R_DC_0,
    SC_R_DC_1,
};

sc_rsrc_t master[] = {
    SC_R_DC_0,
    SC_R_DC_0_BLIT_OUT,
    SC_R_DC_0_BLIT0,
    SC_R_DC_0_BLIT1,
    SC_R_DC_0_BLIT2,
    SC_R_DC_0_WARP,
    SC_R_DC_0_FRAC0,

    SC_R_DC_1,
    SC_R_DC_1_BLIT_OUT,
    SC_R_DC_1_BLIT0,
    SC_R_DC_1_BLIT1,
    SC_R_DC_1_BLIT2,
    SC_R_DC_1_WARP,
    SC_R_DC_1_FRAC0,

    /*vpu decoder */
    SC_R_VPU_DEC_0,

    SC_R_VPU_PID0,
    SC_R_VPU_PID1,
    SC_R_VPU_PID2,
    SC_R_VPU_PID3,
    SC_R_VPU_PID4,
    SC_R_VPU_PID5,
    SC_R_VPU_PID6,
    SC_R_VPU_PID7,
};

sc_rsrc_t moveable_1[] = {
    SC_R_VPU,
    SC_R_VPU_DEC_0,
    SC_R_VPU_MU_0,

    SC_R_VPU_PID0,
    SC_R_VPU_PID1,
    SC_R_VPU_PID2,
    SC_R_VPU_PID3,
    SC_R_VPU_PID4,
    SC_R_VPU_PID5,
    SC_R_VPU_PID6,
    SC_R_VPU_PID7,
};

sc_rsrc_t moveable_2[] = {
    SC_R_DC_0,
    SC_R_DC_1,
    SC_R_DC_0_BLIT_OUT,
    SC_R_DC_0_BLIT0,
    SC_R_DC_0_BLIT1,
    SC_R_DC_0_BLIT2,
    SC_R_DC_0_WARP,
    SC_R_DC_0_FRAC0,


    SC_R_DC_1_BLIT_OUT,
    SC_R_DC_1_BLIT0,
    SC_R_DC_1_BLIT1,
    SC_R_DC_1_BLIT2,
    SC_R_DC_1_WARP,
    SC_R_DC_1_FRAC0,
};

static int alloc_part() {
    sc_err_t err;
    sc_ipc_t ipc_handle;

    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("allocate vpu partition ipc port open error\n");
        return -1;
    }
    err = sc_rm_partition_alloc(ipc_handle, &vpu_part, false, true,
            false, false, false);
    if (err)
        printf("vpu part allocate failed\n");

    err = sc_rm_get_partition(ipc_handle, &secure_part);
    err = sc_rm_set_parent(ipc_handle, vpu_part, secure_part);
    if (err)
        printf("set secure partition as parent for vpu part failed : %d\n", err);

    sc_ipc_close(ipc_handle);

    return err;
}

static int mem_permission() {
    sc_err_t err;
    sc_ipc_t ipc_handle;
    sc_rm_mr_t mr_drm, mr_vpu;


    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("mem_permission ipc port open error\n");
        return -1;
    }
    err = sc_rm_find_memreg(ipc_handle, &mr_drm, SECURE_HEAP_BASE, SECURE_HEAP_BASE + SECURE_HEAP_SIZE - 1);
    if (err)
        printf("find secure heap region from secure part failed err:%d\n",err);

    err = sc_rm_assign_memreg(ipc_handle, vpu_part, mr_drm);
    if (err)
        printf("assigne secure memory to vpu part failed err:%d\n",err);

    /* configure secure part/os part/vpu_part/dpu_part can r/w secure memory in secure os */
    err = sc_rm_set_memreg_permissions(ipc_handle, mr_drm, vpu_part, SC_RM_PERM_SEC_RW);
    if (err)
        printf("configure secure memory permission to vpu part failed err : %d\n", err);

    err = sc_rm_set_memreg_permissions(ipc_handle, mr_drm, secure_part, SC_RM_PERM_SEC_RW);
    if (err)
        printf("configure secure memory permission to secure part failed err : %d\n", err);

    err = sc_rm_set_memreg_permissions(ipc_handle, mr_drm, dpu_part, SC_RM_PERM_SEC_RW);
    if (err)
        printf("configure secure memory permission to dpu part failed err: %d\n", err);

    /* configure vpu_part to vpu firmware memory permission */
    err = sc_rm_find_memreg(ipc_handle, &mr_vpu, VPU_FIRMWARE_BASE, VPU_FIRMWARE_BASE + VPU_FIRMWARE_SIZE - 1);
    if (err)
        printf("find vpu boot memory region from secure part failed err:%d\n",err);

    err = sc_rm_assign_memreg(ipc_handle, vpu_part, mr_vpu);
    if (err)
        printf("assign vpu firmware buffer to vpu part failed err : %d\n",err);

    err = sc_rm_set_memreg_permissions(ipc_handle, mr_vpu, vpu_part, SC_RM_PERM_FULL);
    if (err)
        printf("configure vpu memory permission to vpu part failed err:%d\n",err);

    err = sc_rm_set_memreg_permissions(ipc_handle, mr_vpu, secure_part, SC_RM_PERM_SEC_RW);
    if (err)
        printf("configure vpu memory permission to secure part failed err:%d\n",err);


    sc_ipc_close(ipc_handle);
    return err;
}

int imx_scu_rpc_call(struct smc32_args* args) {
    sc_err_t err;
    sc_ipc_t ipc_handle;
    sc_rm_pt_t pt;
    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("imx_scu_rpc_call ipc port open error\n");
        return -1;
    }

    u32 rsrc = args->params[0];
    u32 ctrl = args->params[1];
    u32 val = args->params[2];
    err = sc_rm_get_resource_owner(ipc_handle, rsrc, &pt);
    if (pt == os_part) {
        return RES_OWNED_BY_LINUX;
    }

    err = sc_misc_set_control(ipc_handle, rsrc, ctrl, val);
    if (err)
        printf("misc control failed rsrc=%u, ctrl=%u, val=%u err=%d\n",
                rsrc, ctrl, val, err);

    sc_ipc_close(ipc_handle);
    return err;
}


static int configure_secure_vpu() {
    sc_err_t err;
    sc_ipc_t ipc_handle;

    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("configure_secure_vpu ipc port open error\n");
        return -1;
    }
    err = sc_rm_set_resource_movable(ipc_handle, SC_R_ALL, SC_R_ALL, SC_FALSE);
    if (err) {
        printf("set all of resource not be movable failed err:%d \n",err);
    } else {
        for(uint32_t i = 0; i < sizeof(moveable_1)/sizeof(moveable_1[0]); i++) {
            err = sc_rm_set_resource_movable(ipc_handle, moveable_1[i], moveable_1[i], SC_TRUE);
            if (err)
                printf("set resource:%u movable failed err:%d\n",i ,err);
        }
        err = sc_rm_move_all(ipc_handle, os_part, vpu_part, SC_TRUE, SC_TRUE);
        if (err) {
            printf("Move movable resource to vpu part failed err:%d\n", err);
        } else {
            for (uint32_t j = 0; j < sizeof(master)/sizeof(master[0]); j++) {
                err = sc_rm_set_master_attributes(ipc_handle, master[j], SC_RM_SPA_ASSERT, SC_RM_SPA_ASSERT , SC_FALSE);
                if (err)
                        printf("set master:%u attribute failed err=%d\n",j ,err);
            }

            for (uint32_t i = 0; i < sizeof(secure_wr_access_allowed)/sizeof(secure_wr_access_allowed[0]); i++) {
                err = sc_rm_set_peripheral_permissions(ipc_handle, secure_wr_access_allowed[i], os_part, SC_RM_PERM_SEC_RW);
                if (err)
                        printf("set peripheral:%u permissions for os_part failed:%u\n", secure_wr_access_allowed[i], err);
            }

            err = sc_rm_set_peripheral_permissions(ipc_handle, SC_R_VPU_MU_0, os_part, SC_RM_PERM_FULL);
            if (err)
                    printf("set peripheral permissions for os_part rsrc %u failed %d\n", SC_R_VPU_MU_0, err);
        }
    }

    sc_ipc_close(ipc_handle);
    return err;
}

static int configure_secure_dpu() {
    sc_err_t err;
    sc_ipc_t ipc_handle;

    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("configure_secure_dpu ipc port open error\n");
        return -1;
    }
    err = sc_rm_set_resource_movable(ipc_handle, SC_R_ALL, SC_R_ALL, SC_FALSE);
    if (err) {
        printf("set resource not be movable failed err:%d \n",err);
    } else {
        for(uint32_t i = 0; i < sizeof(moveable_2)/sizeof(moveable_2[0]); i++) {
            err = sc_rm_set_resource_movable(ipc_handle, moveable_2[i], moveable_2[i], SC_TRUE);
            if (err)
                    printf("set resource:%u movable failed:%d\n", i, err);
        }
        err = sc_rm_move_all(ipc_handle, os_part, dpu_part, SC_TRUE, SC_TRUE);
        if (err) {
            printf("move all of dpu resource failed:%d\n",err);
        } else {
            for (uint32_t j = 0; j < sizeof(ns_access_allowed)/sizeof(ns_access_allowed[0]); j++) {
                err = sc_rm_set_peripheral_permissions(ipc_handle, ns_access_allowed[j], os_part, SC_RM_PERM_FULL);
                if (err)
                    printf("set peripheral:%u permissions to os_part failed:%d\n", j, err);
            }
        }
    }

    sc_ipc_close(ipc_handle);
    return err;

}

static int configure_nonsecure_vpu() {
    sc_err_t err;
    sc_ipc_t ipc_handle;

    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("configure_nonsecure_vpu ipc port open error\n");
        return -1;
    }


    err = sc_rm_set_resource_movable(ipc_handle, SC_R_ALL, SC_R_ALL, SC_FALSE);
    if (err) {
        printf("set_resource_movable of vpu failed err=%d \n",err);
    } else {
        for(uint32_t i = 0; i < sizeof(moveable_1)/sizeof(moveable_1[0]); i++) {
            err = sc_rm_set_resource_movable(ipc_handle, moveable_1[i], moveable_1[i], SC_TRUE);
            if (err)
                printf("set resource:%u movable failed:%d\n",i, err);
        }
        err = sc_rm_move_all(ipc_handle, vpu_part, os_part, SC_TRUE, SC_TRUE);
        if (err)
            printf("Move all of vpu resource to os part failed:%d\n",err);
    }

    sc_ipc_close(ipc_handle);
    return err;
}

static int configure_nonsecure_dpu() {
    sc_err_t err;
    sc_ipc_t ipc_handle;
    sc_rm_pt_t pt;

    if (sc_ipc_open(&ipc_handle, SC_IPC_BASE) != SC_ERR_NONE) {
        printf("configure_nonsecure_dpu ipc port open error\n");
        return -1;
    }

    err = sc_rm_get_resource_owner(ipc_handle, SC_R_DC_0, &pt);
    if (pt == os_part) {
        printf("dpu resource are in the os part\n");
        return 0;
    }

    err = sc_rm_set_resource_movable(ipc_handle, SC_R_ALL, SC_R_ALL, SC_FALSE);
    if (err) {
        printf("set resource not be movable failed:%d \n",err);
    } else {
        /* dpu resource to dpu part */
        for(uint32_t i = 0; i < sizeof(moveable_2)/sizeof(moveable_2[0]); i++) {
            err = sc_rm_set_resource_movable(ipc_handle, moveable_2[i], moveable_2[i], SC_TRUE);
            if (err)
                printf("set resource:%u movable failed:%d\n", i, err);
        }
        err = sc_rm_move_all(ipc_handle, dpu_part, os_part, SC_TRUE, SC_TRUE);
        if (err)
            printf("Move all of dpu resource to os paart failed:%d\n",err);
        /* end */
    }

    sc_ipc_close(ipc_handle);
    return err;
}

static int imx_scu_power_set(struct smc32_args* args) {
    bool power_on = args->params[0];
    int ret = 0;
    if (power_on) {
        printf("configure secure pipeline\n");
        ret = configure_secure_dpu();
        if (ret)
            return ret;
        ret = configure_secure_vpu();
        if (ret)
            return ret;
        return vpu_part;
    } else {
        printf("configure non-secure\n");
        ret = configure_nonsecure_dpu();
        if (ret)
            return ret;
        return configure_nonsecure_vpu();
    }
}

static int imx_scu_dpu_power_set(struct smc32_args* args) {
    bool power_on = args->params[0];
    if (power_on) {
        return 0;
    } else {
        printf("DPU crtc disable\n");
        return configure_nonsecure_dpu();
    }
}

static int32_t sys_scu_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr) {
    switch (cmd) {
        case SCU_ALLOC_PART:
            return alloc_part();
        case SCU_MEM_PERMISSION:
            return mem_permission();
    }
    return 0;
}

static long scu_fastcall(struct smc32_args* args) {

    if (args->smc_nr == SMC_SCU_MISC_CONTROL) {
        return imx_scu_rpc_call(args);
    } else if (args->smc_nr == SMC_WV_POWER_SET) {
        return imx_scu_power_set(args);
    } else if (args->smc_nr == SMC_WV_DPU_POWER_SET) {
        return imx_scu_dpu_power_set(args);
    }
    return 0;
}

static const struct sys_fd_ops scu_ops = {
    .ioctl = sys_scu_ioctl,
};

void platform_init_scu(uint level) {
    install_sys_fd_handler(SYSCALL_PLATFORM_FD_SCU, &scu_ops);

    /* Get os part number and dpu partition number */
    struct smc_ret8 smc_ret;
    smc_ret = smc8(IMX_SIP_GET_PARTITION_NUMBER, 0, 0, 0, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 == 0) {
        os_part = smc_ret.r1;
        dpu_part = smc_ret.r2;
    } else {
        printf("SMC_GET_PARITION_NUMBER Get failed ret=%d\n", (int)smc_ret.r0);
    }
}

static struct smc32_entity scu_entity = {
    .fastcall_handler = scu_fastcall,
};

void scu_smcall_init(uint level) {
    sm_register_entity(SMC_ENTITY_SCU, &scu_entity);
}

LK_INIT_HOOK(scu_driver, scu_smcall_init, LK_INIT_LEVEL_PLATFORM);
LK_INIT_HOOK(imx_scu_ioctl, platform_init_scu, LK_INIT_LEVEL_PLATFORM + 1);
