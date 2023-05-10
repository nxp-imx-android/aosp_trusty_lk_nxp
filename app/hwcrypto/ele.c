/*
 * Copyright 2023 NXP
 */

#define TLOG_TAG "hwkey_ele"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <uapi/err.h>
#include <lk/compiler.h>
#include <sys/types.h>
#include <trusty_log.h>
#include <platform/imx_ele.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/hkdf.h>

#define HUK_SIZE 16
#define RPMB_EMMC_CID_SIZE 16
#define RPMB_SS_AUTH_KEY_SIZE 32
extern bool emmc_cid_provisioned;
extern uint8_t emmc_cid[RPMB_EMMC_CID_SIZE];
static uint8_t ele_context[16] = {"TEE_for_HUK_ELE"};
static uint8_t huk[HUK_SIZE];
static bool huk_provisioned = false;
static uint8_t ele_derive_salt[] = {"TRUSTY_ELE_DERIVE"};

extern long _trusty_ioctl(uint32_t fd, uint32_t req, void *buf);
int get_ele_huk(void)
{
    struct ele_huk_msg msg;
    int res = 0;

    msg.hwkey = huk;
    msg.ctx = ele_context;
    msg.key_size = HUK_SIZE;
    msg.ctx_size = sizeof(ele_context);

    res = _trusty_ioctl(SYSCALL_PLATFORM_FD_ELE, ELE_DERIVE_HUK, &msg);
    if (res) {
        TLOGE("%s: failed to generate huk!\n", __func__);
        return -1;
    } else {
        huk_provisioned = true;
        return 0;
    }
}

int generate_ele_rpmb_key(uint8_t *kbuf, size_t* klen)
{
    HMAC_CTX hmac_ctx;

    // check if we have provisioned the emmc cid and huk
    if (!emmc_cid_provisioned || !huk_provisioned) {
        TLOGE("%s: emmc cid or huk is not provisioned!\n", __func__);
        return -1;
    }

    // generate the final rpmb key
    HMAC_CTX_init(&hmac_ctx);
    if (!HMAC_Init_ex(&hmac_ctx, huk, HUK_SIZE, EVP_sha256(), NULL)) {
        TLOGE("%s: hmac init failed!\n", __func__);
        return -1;
    }
    if (!HMAC_Update(&hmac_ctx, emmc_cid, RPMB_EMMC_CID_SIZE)) {
        TLOGE("%s: hmac update failed!\n", __func__);
        return -1;
    }
    if (!HMAC_Final(&hmac_ctx, kbuf, NULL)) {
        TLOGE("%s: hmac final failed!\n", __func__);
        return -1;
    }
    *klen = RPMB_SS_AUTH_KEY_SIZE;

    return 0;
}

int get_ele_derived_key(uint8_t *key, size_t key_size, uint8_t *ctx, size_t ctx_size)
{
    if (!huk_provisioned) {
        TLOGE("%s: huk is not provisioned!\n", __func__);
        return -1;
    }

    if (!HKDF(key, key_size, EVP_sha256(), huk, sizeof(huk),
              ele_derive_salt, sizeof(ele_derive_salt), ctx, sizeof(ctx))) {
        TLOGE("HKDF failed to derive key!\n");
        return -1;
    }

    return 0;
}
