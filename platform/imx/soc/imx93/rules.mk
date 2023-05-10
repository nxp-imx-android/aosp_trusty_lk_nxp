# Copyright 2023 NXP
#

CUR_DIR := $(GET_LOCAL_DIR)

MODULE_SRCS += \
	$(CUR_DIR)/start.S \
	$(CUR_DIR)/platform.c

CUR_DIR :=
