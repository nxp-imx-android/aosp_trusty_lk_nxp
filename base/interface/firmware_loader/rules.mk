LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_EXPORT_INCLUDES += $(LOCAL_DIR)/include

include make/library.mk
