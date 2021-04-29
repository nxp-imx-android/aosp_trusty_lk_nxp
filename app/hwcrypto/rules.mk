#
# Copyright (C) 2016-2017 The Android Open Source Project
# Copyright 2017 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/../../platform/imx/soc/$(PLATFORM_SOC)/include/nxp_hwcrypto_manifest.json

MODULE_CONSTANTS := \
	$(LOCAL_DIR)/../../platform/imx/soc/$(PLATFORM_SOC)/include/nxp_hwcrypto_memmap_consts.json \
	$(LOCAL_DIR)/nxp_hwcrypto_consts.json \
	$(LOCAL_DIR)/nxp_hwcrypto_uuid_consts.json \

MODULE_SRCS := \
	$(LOCAL_DIR)/main.c \
	$(LOCAL_DIR)/hwrng_srv.c \
	$(LOCAL_DIR)/hwkey_srv.c \
	$(LOCAL_DIR)/hwcrypto_srv.c \
	$(LOCAL_DIR)/hwkey_srv_provider.c \
	$(LOCAL_DIR)/hwrng_srv_provider.c \
	$(LOCAL_DIR)/hwcrypto_srv_provider.c \
	$(LOCAL_DIR)/caam.c \

MODULE_INCLUDES := \
	$(LOCAL_DIR)/../../platform/imx/soc/$(PLATFORM_SOC)/include

MODULE_LIBRARY_DEPS := \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/interface/hwrng \
	trusty/user/base/interface/hwkey \
	trusty/user/base/interface/hwcrypto \
	external/boringssl \

ifneq ($(APPLOADER_SIGN_PUBLIC_KEY_0_FILE),)
MODULE_COMPILEFLAGS += \
	-DAPPLOADER_SIGN_PUBLIC_KEY_0_FILE=\"$(APPLOADER_SIGN_PUBLIC_KEY_0_FILE)\"
endif

ifneq ($(APPLOADER_SIGN_PUBLIC_KEY_1_FILE),)
MODULE_COMPILEFLAGS += \
	-DAPPLOADER_SIGN_PUBLIC_KEY_1_FILE=\"$(APPLOADER_SIGN_PUBLIC_KEY_1_FILE)\"
endif

ifneq ($(APPLOADER_ENCRYPT_KEY_0_FILE),)
MODULE_COMPILEFLAGS += \
	-DAPPLOADER_ENCRYPT_KEY_0_FILE=\"$(APPLOADER_ENCRYPT_KEY_0_FILE)\"
endif

ifneq ($(APPLOADER_ENCRYPT_KEY_1_FILE),)
MODULE_COMPILEFLAGS += \
	-DAPPLOADER_ENCRYPT_KEY_1_FILE=\"$(APPLOADER_ENCRYPT_KEY_1_FILE)\"
endif

include make/trusted_app.mk
