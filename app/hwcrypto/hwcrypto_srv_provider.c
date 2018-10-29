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

#include "caam.h"
#include "common.h"
#include "hwcrypto_srv_priv.h"
#include <interface/hwcrypto/hwcrypto.h>

#define TLOG_LVL TLOG_LVL_DEFAULT
#define TLOG_TAG "hwcrypto_caam"
#include "tlog.h"

int calculate_hash(uint32_t in_paddr, uint32_t in_len,
                   uint32_t out_paddr, enum hash_algo algo) {
    if (caam_hash_pa(in_paddr, out_paddr, in_len, algo) != 0)
	    return HWCRYPTO_ERROR_INTERNAL;
    else
	    return HWCRYPTO_ERROR_NONE;
}

void hwcrypto_init_srv_provider(void) {
    int rc;

    TLOGE("Init HWCRYPTO service provider\n");
    /* Nothing to initialize here, just start service */
    rc = hwcrypto_start_service();
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to start HWCRYPTO service\n", rc);
    }
}
