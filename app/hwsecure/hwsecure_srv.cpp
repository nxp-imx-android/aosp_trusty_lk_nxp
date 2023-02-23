/*
 * Copyright 2023 NXP
 *
 */

#include <interface/hwsecure/hwsecure.h>
#include <lib/tipc/tipc.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <string.h>
#include <lk/err_ptr.h>
#include <lib/tipc/tipc_srv.h>
#include "hwsecure_srv.h"
#include "hwsecure.h"
#include "imx-regs.h"

#define TLOG_TAG "hwsecure_srv"

static hwservice_context ctx;

struct chan_uuid {
    handle_t chan;
    struct uuid peer;
};

static struct chan_uuid uuid_list[2] = {
    {
        .chan = -1,
        .peer = {0, 0, 0, { 0 }},
    },
    {
        .chan = -1,
        .peer = {0, 0, 0, { 0 }},
    },
};

// 405729b4-c12d-45d9-ae97-0f25aaa204e4
const static struct uuid secure_fb_impl_ta_uuid = {
    0x405729b4,
    0xc12d,
    0x45d9,
    {0xae, 0x97, 0x0f, 0x25, 0xaa, 0xa2, 0x04, 0xe4},
};

// 9c0e58c8-1465-4649-a147-55deb3366205
const static struct uuid hwsecure_client_ta_uuid = {
    0x9c0e58c8,
    0x1465,
    0x4649,
    {0xa1, 0x47, 0x55, 0xde, 0xb3, 0x36, 0x62, 0x05},
};

// 7dee2364-c036-425b-b086-df0f6c233c1b
const static struct uuid confirmationui_ta_uuid = {
    0x7dee2364,
    0xc036,
    0x425b,
    {0xb0, 0x86, 0xdf, 0x0f, 0x6c, 0x23, 0x3c, 0x1b},
};


static bool check_uuid_equal(const struct uuid* a, const struct uuid* b) {
    return memcmp(a, b, sizeof(struct uuid)) == 0;
}

static const struct uuid *allow_uuids[] = {
    &secure_fb_impl_ta_uuid,
    &hwsecure_client_ta_uuid,
    &confirmationui_ta_uuid,
};

static struct tipc_port_acl acl = {
    .flags = IPC_PORT_ALLOW_TA_CONNECT,
    .uuid_num = 3,
    .uuids = allow_uuids,
};

static struct tipc_port port = {
    .name = HWSECURE_PORT_NAME,
    .msg_max_size = HWSECURE_MAX_MSG_SIZE,
    .msg_queue_len = 1,
    .acl = &acl,
    .priv = &ctx,
};

static int hwsecure_on_connect(const struct tipc_port* port,
                                handle_t chan,
                                const struct uuid* peer,
                                void** ctx_p) {
    uint32_t i = 0;
    struct chan_uuid *ptr = uuid_list;

    TLOGI("hwsecure_on_connect!\n");
    for (i = 0; i < sizeof(uuid_list)/sizeof(struct chan_uuid); i++) {
        if (ptr->chan == -1) {
            ptr->chan = chan;
            memcpy(&(ptr->peer), peer, sizeof(struct uuid));
            return NO_ERROR;
        }
        ptr++;
    }

    TLOGE("Exceed the max hwsecure max channel limit!\n");
    return ERR_GENERIC;
}

static void hwsecure_on_disconnect(const struct tipc_port* port,
                                    handle_t chan,
                                    void* ctx) {
    uint32_t i = 0;
    struct chan_uuid *ptr = uuid_list;

    TLOGI("hwsecure_on_disconnect!\n");
    for (i = 0; i < sizeof(uuid_list)/sizeof(struct chan_uuid); i++) {
        if (ptr->chan == chan) {
            ptr->chan = -1;
            memset(&(ptr->peer), 0, sizeof(struct uuid));
            break;
        }
        ptr++;
    }

    if (i == sizeof(uuid_list)/sizeof(struct chan_uuid))
        TLOGE("Channel connection info free failed!\n");
}

static int hwsecure_on_message(const struct tipc_port* port,
                                handle_t chan,
                                void* _ctx) {
    int rc;
    uint32_t list = 0;
    struct hwsecure_req req;
    struct chan_uuid *ptr = uuid_list;

    rc = tipc_recv1(chan, sizeof(req), &req, sizeof(req));
    if (rc < 0) {
        TLOGE("failed to recv req \n");
        return ERR_GENERIC;
    }

    for (list = 0; list < sizeof(uuid_list)/sizeof(struct chan_uuid); list++) {
        if (ptr->chan == chan) {
            break;
        }
        ptr++;
    }

    if (list == sizeof(uuid_list)/sizeof(struct chan_uuid)) {
        TLOGE("No matching connection find!\n");
        return ERR_GENERIC;
    }

    switch(req.cmd) {
#if defined(MACH_IMX8MQ)
        case HWSECURE_DCSS_SECURE_ACCESS:
        case HWSECURE_DCSS_NON_SECURE_ACCESS:
             if (check_uuid_equal(&(ptr->peer), &confirmationui_ta_uuid)) {
                  return set_dcss_secure(req.cmd);
             } else {
                  TLOGE("UUID doesn't match!\n");
                  return ERR_GENERIC;
             }
             break;
        case HWSECURE_SET_RDC_MEM_REGION:
             if ((check_uuid_equal(&(ptr->peer), &hwsecure_client_ta_uuid)) ||
                 (check_uuid_equal(&(ptr->peer), &confirmationui_ta_uuid))) {
                 return set_rdc_mem_region();
             } else {
                 TLOGE("UUID doesn't match!\n");
                 return ERR_GENERIC;
             }
             break;
#elif defined(MACH_IMX8MM) || defined(MACH_IMX8MP)
        case HWSECURE_LCDIF_SECURE_ACCESS:
        case HWSECURE_LCDIF_NON_SECURE_ACCESS:
            if (check_uuid_equal(&(ptr->peer), &secure_fb_impl_ta_uuid))
                return set_lcdif_secure(req.cmd);
            else {
                TLOGE("UUID doesn't match!\n");
                return ERR_GENERIC;
            }
            break;
#elif defined(MACH_IMX8ULP)
        case HWSECURE_DCNANO_SECURE_ACCESS:
        case HWSECURE_DCNANO_NON_SECURE_ACCESS:
             if (check_uuid_equal(&(ptr->peer), &secure_fb_impl_ta_uuid) ||
                 check_uuid_equal(&(ptr->peer), &confirmationui_ta_uuid)) {
                  return set_dcnano_secure(req.cmd);
             } else {
                  TLOGE("UUID doesn't match!\n");
                  return ERR_GENERIC;
             }
             break;
        case HWSECURE_IME_SECURE_ACCESS:
        case HWSECURE_IME_NON_SECURE_ACCESS:
             if (check_uuid_equal(&(ptr->peer), &hwsecure_client_ta_uuid)) {
                  return set_ime_secure(req.cmd, chan);
             } else {
                  TLOGE("UUID doesn't match!\n");
                  return ERR_GENERIC;
             }
             break;
        case HWSECURE_IME_GET_SECURE_MODE:
             if (check_uuid_equal(&(ptr->peer), &hwsecure_client_ta_uuid)) {
                  int mode;
                  int rc = get_ime_secure_mode(mode);
                  if (rc == 0) {
                      rc = tipc_send1(chan, &mode, sizeof(mode));
                  }
                  return rc;
             } else {
                  TLOGE("UUID doesn't match!\n");
                  return ERR_GENERIC;
             }
             break;
#endif
        case HWSECURE_WV_G2D_SECURE:
        case HWSECURE_WV_G2D_NON_SECURE:
                if (check_uuid_equal(&(ptr->peer), &hwsecure_client_ta_uuid)) {
                    return set_widevine_g2d_secure_mode(req.cmd);
                } else {
                    TLOGE("UUID doesn't match!\n");
                    return ERR_GENERIC;
                }
        case HWSECURE_WV_GET_G2D_SECURE_MODE:
                if (check_uuid_equal(&(ptr->peer), &hwsecure_client_ta_uuid)) {
                    int mode;
                    int rc = get_widevine_g2d_secure_mode(mode);
                    if (rc == 0) {
                        rc = tipc_send1(chan, &mode, sizeof(mode));
                        TLOGE("cur_secure_mode is %d \n", mode);
                    }
                    return rc;
                } else {
                    TLOGE("UUID doesn't match!\n");
                    return ERR_GENERIC;
                }
        default:
            return ERR_INVALID_ARGS;
    }
    return NO_ERROR;
}

int add_hwsecure_service(struct tipc_hset *hset, handle_t *chan) {
    if (!hset || !chan)
        return ERR_INVALID_ARGS;

    ctx.chan = chan;

    static struct tipc_srv_ops ops = {
        .on_connect = hwsecure_on_connect,
        .on_message = hwsecure_on_message,
        .on_disconnect = hwsecure_on_disconnect,
    };

    return tipc_add_service(hset, &port, 1, 2, &ops);
}
