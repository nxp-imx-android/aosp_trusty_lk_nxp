#Copyright 2023 NXP

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
	$(LOCAL_DIR)/widevine_l3.c \

MODULE_INCLUDES += \
	trusty/hardware/nxp/platform/imx/common/include \
	trusty/hardware/nxp/platform/imx/soc/$(PLATFORM_SOC)/include \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/lib/tipc \
	trusty/hardware/nxp/base/lib/hwsecure \

include make/trusted_app.mk
