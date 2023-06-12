NXP_OPENSSL_STUBS_DIR := $(GET_LOCAL_DIR)

MODULE_EXPORT_INCLUDES += \
	trusty/hardware/nxp/platform/imx/common/include

ifeq (true,$(call TOBOOL,$(WITH_CAAM_SUPPORT)))
MODULE_DEFINES += \
	WITH_CAAM_SUPPORT=1
endif

ifeq (true,$(call TOBOOL,$(WITH_ELE_SUPPORT)))
MODULE_DEFINES += \
	WITH_ELE_SUPPORT=1
endif

MODULE_SRCS += \
	$(NXP_OPENSSL_STUBS_DIR)/rand.c \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/rng \

