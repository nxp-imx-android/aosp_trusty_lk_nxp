/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*!
 * File containing client-side RPC functions for the MISC service. These
 * functions are ported to clients that communicate to the SC.
 *
 * @addtogroup MISC_SVC
 * @{
 */

/* Includes */

#include <sci/types.h>
#include <sci/svc/rm/api.h>
#include <sci/svc/misc/api.h>
#include <sci/rpc.h>
#include "rpc.h"

/* Local Defines */

/* Local Types */

/* Local Functions */

sc_err_t sc_misc_set_control(sc_ipc_t ipc, sc_rsrc_t resource,
    sc_ctrl_t ctrl, uint32_t val)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_SET_CONTROL);
    RPC_U32(&msg, 0U) = U32(ctrl);
    RPC_U32(&msg, 4U) = U32(val);
    RPC_U16(&msg, 8U) = U16(resource);
    RPC_SIZE(&msg) = 4U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_get_control(sc_ipc_t ipc, sc_rsrc_t resource,
    sc_ctrl_t ctrl, uint32_t *val)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_GET_CONTROL);
    RPC_U32(&msg, 0U) = U32(ctrl);
    RPC_U16(&msg, 4U) = U16(resource);
    RPC_SIZE(&msg) = 3U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (val != NULL)
    {
        *val = RPC_U32(&msg, 0U);
    }

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_set_max_dma_group(sc_ipc_t ipc, sc_rm_pt_t pt,
    sc_misc_dma_group_t max)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_SET_MAX_DMA_GROUP);
    RPC_U8(&msg, 0U) = U8(pt);
    RPC_U8(&msg, 1U) = U8(max);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_set_dma_group(sc_ipc_t ipc, sc_rsrc_t resource,
    sc_misc_dma_group_t group)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_SET_DMA_GROUP);
    RPC_U16(&msg, 0U) = U16(resource);
    RPC_U8(&msg, 2U) = U8(group);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

void sc_misc_debug_out(sc_ipc_t ipc, uint8_t ch)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_DEBUG_OUT);
    RPC_U8(&msg, 0U) = U8(ch);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    return;
}

sc_err_t sc_misc_waveform_capture(sc_ipc_t ipc, sc_bool_t enable)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_WAVEFORM_CAPTURE);
    RPC_U8(&msg, 0U) = B2U8(enable);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

void sc_misc_build_info(sc_ipc_t ipc, uint32_t *build,
    uint32_t *commit)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_BUILD_INFO);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (build != NULL)
    {
        *build = RPC_U32(&msg, 0U);
    }

    if (commit != NULL)
    {
        *commit = RPC_U32(&msg, 4U);
    }

    return;
}

void sc_misc_api_ver(sc_ipc_t ipc, uint16_t *cl_maj,
    uint16_t *cl_min, uint16_t *sv_maj, uint16_t *sv_min)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_API_VER);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (cl_maj != NULL)
    {
        *cl_maj = SCFW_API_VERSION_MAJOR;
    }

    if (cl_min != NULL)
    {
        *cl_min = SCFW_API_VERSION_MINOR;
    }

    if (sv_maj != NULL)
    {
        *sv_maj = RPC_U16(&msg, 4U);
    }

    if (sv_min != NULL)
    {
        *sv_min = RPC_U16(&msg, 6U);
    }

    return;
}

void sc_misc_unique_id(sc_ipc_t ipc, uint32_t *id_l,
    uint32_t *id_h)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_UNIQUE_ID);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (id_l != NULL)
    {
        *id_l = RPC_U32(&msg, 0U);
    }

    if (id_h != NULL)
    {
        *id_h = RPC_U32(&msg, 4U);
    }

    return;
}

sc_err_t sc_misc_set_ari(sc_ipc_t ipc, sc_rsrc_t resource,
    sc_rsrc_t resource_mst, uint16_t ari, sc_bool_t enable)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_SET_ARI);
    RPC_U16(&msg, 0U) = U16(resource);
    RPC_U16(&msg, 2U) = U16(resource_mst);
    RPC_U16(&msg, 4U) = U16(ari);
    RPC_U8(&msg, 6U) = B2U8(enable);
    RPC_SIZE(&msg) = 3U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

void sc_misc_boot_status(sc_ipc_t ipc, sc_misc_boot_status_t status)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_BOOT_STATUS);
    RPC_U8(&msg, 0U) = U8(status);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_TRUE);

    return;
}

sc_err_t sc_misc_boot_done(sc_ipc_t ipc, sc_rsrc_t cpu)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_BOOT_DONE);
    RPC_U16(&msg, 0U) = U16(cpu);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_otp_fuse_read(sc_ipc_t ipc, uint32_t word, uint32_t *val)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_OTP_FUSE_READ);
    RPC_U32(&msg, 0U) = U32(word);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (val != NULL)
    {
        *val = RPC_U32(&msg, 0U);
    }

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_otp_fuse_write(sc_ipc_t ipc, uint32_t word, uint32_t val)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_OTP_FUSE_WRITE);
    RPC_U32(&msg, 0U) = U32(word);
    RPC_U32(&msg, 4U) = U32(val);
    RPC_SIZE(&msg) = 3U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_set_temp(sc_ipc_t ipc, sc_rsrc_t resource,
    sc_misc_temp_t temp, int16_t celsius, int8_t tenths)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_SET_TEMP);
    RPC_U16(&msg, 0U) = U16(resource);
    RPC_I16(&msg, 2U) = I16(celsius);
    RPC_U8(&msg, 4U) = U8(temp);
    RPC_I8(&msg, 5U) = I8(tenths);
    RPC_SIZE(&msg) = 3U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_get_temp(sc_ipc_t ipc, sc_rsrc_t resource,
    sc_misc_temp_t temp, int16_t *celsius, int8_t *tenths)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_GET_TEMP);
    RPC_U16(&msg, 0U) = U16(resource);
    RPC_U8(&msg, 2U) = U8(temp);
    RPC_SIZE(&msg) = 2U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (celsius != NULL)
    {
        *celsius = RPC_I16(&msg, 0U);
    }

    result = RPC_R8(&msg);
    if (tenths != NULL)
    {
        *tenths = RPC_I8(&msg, 2U);
    }

    return (sc_err_t) result;
}

void sc_misc_get_boot_dev(sc_ipc_t ipc, sc_rsrc_t *dev)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_GET_BOOT_DEV);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (dev != NULL)
    {
        *dev = RPC_U16(&msg, 0U);
    }

    return;
}

sc_err_t sc_misc_get_boot_type(sc_ipc_t ipc, sc_misc_bt_t *type)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_GET_BOOT_TYPE);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    if (type != NULL)
    {
        *type = RPC_U8(&msg, 0U);
    }

    return (sc_err_t) result;
}

sc_err_t sc_misc_get_boot_container(sc_ipc_t ipc, uint8_t *idx)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_GET_BOOT_CONTAINER);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    result = RPC_R8(&msg);
    if (idx != NULL)
    {
        *idx = RPC_U8(&msg, 0U);
    }

    return (sc_err_t) result;
}

void sc_misc_get_button_status(sc_ipc_t ipc, sc_bool_t *status)
{
    sc_rpc_msg_t msg;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_GET_BUTTON_STATUS);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (status != NULL)
    {
        *status = U2B(RPC_U8(&msg, 0U));
    }

    return;
}

sc_err_t sc_misc_rompatch_checksum(sc_ipc_t ipc, uint32_t *checksum)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_ROMPATCH_CHECKSUM);
    RPC_SIZE(&msg) = 1U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    if (checksum != NULL)
    {
        *checksum = RPC_U32(&msg, 0U);
    }

    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

sc_err_t sc_misc_board_ioctl(sc_ipc_t ipc, uint32_t *parm1,
    uint32_t *parm2, uint32_t *parm3)
{
    sc_rpc_msg_t msg;
    uint8_t result;

    RPC_VER(&msg) = SC_RPC_VERSION;
    RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
    RPC_FUNC(&msg) = U8(MISC_FUNC_BOARD_IOCTL);
    RPC_U32(&msg, 0U) = *PTR_U32(parm1);
    RPC_U32(&msg, 4U) = *PTR_U32(parm2);
    RPC_U32(&msg, 8U) = *PTR_U32(parm3);
    RPC_SIZE(&msg) = 4U;

    sc_call_rpc(ipc, &msg, SC_FALSE);

    *parm1 = RPC_U32(&msg, 0U);
    *parm2 = RPC_U32(&msg, 4U);
    *parm3 = RPC_U32(&msg, 8U);
    result = RPC_R8(&msg);
    return (sc_err_t) result;
}

/**@}*/

