
#define TLOG_TAG "secure_fb_ipc"

#include <interface/hwsecure/hwsecure.h>

#include <lib/hwsecure/hwsecure.h>
#include <lib/tipc/tipc.h>
#include <uapi/err.h>
#include <trusty_ipc.h>
#include <trusty_log.h>

int set_lcdif_secure_access(int enable) {
    handle_t chan;
    int rc;

    rc = tipc_connect(&chan, HWSECURE_PORT_NAME);
    if (rc != NO_ERROR) {
        TLOGE("failed to connect to TA %s\n", HWSECURE_PORT_NAME);
        return rc;
    }

    struct hwsecure_req req;
    if (enable)
        req.cmd = HWSECURE_LCDIF_SECURE_ACCESS;
    else
        req.cmd = HWSECURE_LCDIF_NON_SECURE_ACCESS;

    rc = tipc_send1(chan, &req, sizeof(req));

    if (rc != (int)(sizeof(req))) {
        TLOGE("failed to send message and rc=%d\n", rc);
    }

    close(chan);
    return rc;
}

int set_widevine_secure_mode(int secure) {
    handle_t chan;
    int rc;

    rc = tipc_connect(&chan, HWSECURE_PORT_NAME);
    if (rc != NO_ERROR) {
        TLOGE("failed to connect to TA %s\n", HWSECURE_PORT_NAME);
        return rc;
    }

    struct hwsecure_req req;
    if (secure)
        req.cmd = HWSECURE_WV_VPU_SECURE;
    else
        req.cmd = HWSECURE_WV_VPU_NON_SECURE;

    rc = tipc_send1(chan, &req, sizeof(req));

    if (rc != (int)(sizeof(req))) {
        TLOGE("failed to send message and rc=%d\n", rc);
    }

    close(chan);
    return rc;
}

