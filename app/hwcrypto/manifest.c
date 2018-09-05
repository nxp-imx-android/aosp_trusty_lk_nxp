/*
 * Copyright (C) 2016-2017 The Android Open Source Project
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

#include <imx-regs.h>
#include <stddef.h>
#include <stdio.h>
#include <trusty_app_manifest.h>

#include "caam.h"
#include "uuids.h"

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest = {
        .uuid = IMX_HWCRYPTO_UUID,

        .config_options =
                {
                        /* Max HEAP size */
                        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(2 * 4096),
                        /* MMIO regions */
                        TRUSTY_APP_CONFIG_MAP_MEM(CAAM_MMIO_ID,
                                                  CAAM_PHY_BASE_ADDR,
                                                  CAAM_REG_SIZE),
                        TRUSTY_APP_CONFIG_MAP_MEM(CAAM_SEC_RAM_MMIO_ID,
                                                  CAAM_PHY_ARB_BASE_ADDR,
                                                  CAAM_SEC_RAM_SIZE),
#if defined(MACH_IMX7D)
                        TRUSTY_APP_CONFIG_MAP_MEM(CCM_MMIO_ID,
                                                  CCM_PHY_BASE_ADDR,
                                                  CCM_REG_SIZE),
#endif
                },
};
