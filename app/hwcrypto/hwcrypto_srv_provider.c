/*
 * Copyright (C) 2016-2017 The Android Open Source Project
 * Copyright 2018 NXP
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

#include <stdio.h>
#include <uapi/err.h>
#include <sys/mman.h>

#include "caam.h"
#include "common.h"
#include "hwcrypto_srv_priv.h"
#include <interface/hwcrypto/hwcrypto.h>

#define TLOG_LVL TLOG_LVL_DEFAULT
#define TLOG_TAG "hwcrypto_caam"
#include "tlog.h"

static uint8_t skeymod[16] __attribute__((aligned(16))) = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

int caam_encap_blob(uint32_t plain_pa, uint32_t size,
                    uint32_t blob_pa)
{
    int ret;
    uint32_t kmod_pa;
    struct dma_pmem pmem;

    /* Get physical address of skeymod. */
    ret = prepare_dma((void*)skeymod, sizeof(skeymod),
                      DMA_FLAG_TO_DEVICE, &pmem);
    if (ret != 1) {
        TLOGE("failed (%d) to prepare dma buffer\n", ret);
        return HWCRYPTO_ERROR_INTERNAL;
    }
    kmod_pa = (uint32_t)pmem.paddr;

    ret = caam_gen_blob_pa(kmod_pa, sizeof(skeymod),
                           plain_pa, blob_pa, size);

    if (ret != CAAM_SUCCESS)
        return HWCRYPTO_ERROR_INTERNAL;
    else
        return HWCRYPTO_ERROR_NONE;
}

int calculate_hash(uint32_t in_paddr, uint32_t in_len,
                   uint32_t out_paddr, enum hash_algo algo) {
    if (caam_hash_pa(in_paddr, out_paddr, in_len, algo) != 0)
	    return HWCRYPTO_ERROR_INTERNAL;
    else
	    return HWCRYPTO_ERROR_NONE;
}

int gen_rng(uint32_t buf, uint32_t len) {
    if (caam_hwrng_pa(buf, len) != 0)
        return HWCRYPTO_ERROR_INTERNAL;
    else
        return HWCRYPTO_ERROR_NONE;
}

int gen_bkek(uint32_t buf, uint32_t len) {
    if (caam_gen_bkek_key_pa(buf, len) != 0)
        return HWCRYPTO_ERROR_INTERNAL;
    else
        return HWCRYPTO_ERROR_NONE;
}

void hwcrypto_init_srv_provider(void) {
    int rc;

    TLOGD("Init HWCRYPTO service provider\n");
    /* Nothing to initialize here, just start service */
    rc = hwcrypto_start_service();
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to start HWCRYPTO service\n", rc);
    }
}
