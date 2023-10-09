# Copyright (C) 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json
MODULE_CONSTANTS := \
	$(LOCAL_DIR)/../../platform/imx/soc/$(PLATFORM_SOC)/include/nxp_firmware_loader_memmap_consts.json \

MODULE_SRCS += \
	$(LOCAL_DIR)/firmware_loader.c \
	$(LOCAL_DIR)/firmware_loader_package.cpp \
	$(LOCAL_DIR)/cose.cpp \

MODULE_INCLUDES += \
	trusty/kernel/lib/syscall/include \
        trusty/hardware/nxp/platform/imx/common/include \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/lib/libstdc++-trusty \
	trusty/user/base/lib/tipc \
	trusty/user/base/lib/hwaes \
	trusty/user/base/lib/hwkey \
	trusty/user/base/lib/storage \
	trusty/user/base/lib/system_state \
	trusty/hardware/nxp/base/interface/firmware_loader \
	external/boringssl \
	external/libcppbor \

include make/trusted_app.mk
