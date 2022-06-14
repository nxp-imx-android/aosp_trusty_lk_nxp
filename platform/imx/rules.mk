#
# Copyright (c) 2017, Google, Inc. All rights reserved
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

# By default, ARCH is arm.
ifeq (,$(ARCH))
ARCH := arm
ARM_CPU := cortex-a7

# TEE memory phys address and size
MEMBASE ?= 0x9e000000
MEMSIZE ?= 0x02000000

# TEE kernel virt address
KERNEL_BASE ?= $(MEMBASE)

WITH_VIRT_TIMER_INIT := 1
WITH_LIB_SM_MONITOR := 1

# Enable TZ controller
WITH_TZASC ?= true
endif

WITH_LIB_SM ?= 1
WITH_LIB_VERSION ?= 1

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/common/include \
	$(LOCAL_DIR)/soc/$(PLATFORM_SOC)/include \

MODULE_INCLUDES += \
	$(TRUSTY_TOP)/trusty/kernel/services/smc/include \

MODULE_SRCS := \
	$(LOCAL_DIR)/debug.c \
	$(LOCAL_DIR)/platform.c \
	$(LOCAL_DIR)/smc_service_access_policy.c \
	$(LOCAL_DIR)/drivers/imx_caam.c \
	$(LOCAL_DIR)/apploader_mmio_apps.c

ifeq (true,$(call TOBOOL,$(WITH_LCDIF_SUPPORT)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_csu.c \
	$(LOCAL_DIR)/drivers/imx_lcdif.c
endif

ifeq (true,$(call TOBOOL,$(WITH_DCSS_SUPPORT)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_csu.c \
	$(LOCAL_DIR)/drivers/imx_dcss.c
endif

ifeq (true,$(call TOBOOL,$(WITH_DCNANO_SUPPORT)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_dcnano.c
endif


ifeq (true,$(call TOBOOL,$(IMX_USE_LPUART)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_lpuart.c
else
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_uart.c
endif
ifeq (true,$(call TOBOOL,$(WITH_SNVS_DRIVER)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_snvs.c

GLOBAL_DEFINES += \
	USE_IMX_MONOTONIC_TIME=1
endif

ifeq (true, $(call TOBOOL,$(WITH_VPU_DECODER_DRIVER)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_vpu.c
endif

ifeq (true, $(call TOBOOL,$(WITH_VPU_ENCODER_DRIVER)))
MODULE_SRCS += \
	$(LOCAL_DIR)/drivers/imx_vpu_enc.c
endif


#include SOC specific rules if they exists
-include $(LOCAL_DIR)/soc/$(PLATFORM_SOC)/rules.mk

ifeq (true,$(call TOBOOL,$(WITH_TZASC)))
MODULE_SRCS += \
	$(LOCAL_DIR)/tzasc.c

MODULE_DEFINES += \
	WITH_TZASC=1
endif

ifeq (true,$(call TOBOOL,$(WITH_VIRT_TIMER_INIT)))
MODULE_SRCS += \
	$(LOCAL_DIR)/vtimer.S

MODULE_DEFINES += \
	WITH_VIRT_TIMER_INIT=1
endif

MODULE_DEPS += \
	dev/interrupt/arm_gic \
	dev/timer/arm_generic \

GLOBAL_DEFINES += \
	CONFIG_CONSOLE_TTY_BASE=$(CONFIG_CONSOLE_TTY_BASE) \
	MEMBASE=$(MEMBASE) \
	MEMSIZE=$(MEMSIZE) \
	MMU_WITH_TRAMPOLINE=1

LINKER_SCRIPT += \
	$(BUILDDIR)/system-onesegment.ld

include make/module.mk
