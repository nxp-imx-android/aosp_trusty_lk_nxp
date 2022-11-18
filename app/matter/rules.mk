#
# Copyright 2023 The Android Open Source Project
#
# Copyright 2023 NXP
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
NANOPB_DIR := external/nanopb-c

MODULE := $(LOCAL_DIR)

MANIFEST := \
        $(LOCAL_DIR)/manifest.json

# Uncomment below to regenerate the matter.pb.c and matter.pb.h based on matter.proto.
#PB_GEN_DIR := $(call TOBUILDDIR,proto)
#include trusty/user/base/make/compile_proto.mk
#$(eval $(call compile_proto,$(LOCAL_DIR)/matter.proto,$(PB_GEN_DIR)))
#MODULE_SRCS += $(NANOPB_DEPS) $(NANOPB_GENERATED_C)
#MODULE_SRCDEPS += $(NANOPB_GENERATED_HEADER)
#MODULE_INCLOUDES += $(PB_GEN_DIR)

MODULE_INCLUDES += \
        $(LOCAL_DIR) \
        $(LOCAL_DIR)/include \
        $(NANOPB_DIR) \
        trusty/user/base/lib/tipc \

MODULE_SRCS += \
        $(LOCAL_DIR)/matter_ipc.cpp \
        $(LOCAL_DIR)/matter_messages.cpp \
        $(LOCAL_DIR)/serializable.cpp \
        $(LOCAL_DIR)/trusty_matter.cpp \
        $(NANOPB_DIR)/pb_common.c \
        $(NANOPB_DIR)/pb_encode.c \
        $(NANOPB_DIR)/pb_decode.c \
        $(LOCAL_DIR)/matter.pb.c \
        $(LOCAL_DIR)/secure_storage_manager.cpp \
        $(LOCAL_DIR)/p256_keypair.cpp

MODULE_LIBRARY_DEPS += \
        trusty/user/base/lib/libc-trusty \
        trusty/user/base/lib/libstdc++-trusty \
        trusty/user/base/lib/tipc \
        trusty/user/base/lib/rng \
        trusty/user/base/lib/storage \

MODULE_CPPFLAGS := -fno-short-enums
MODULE_COMPILEFLAGS := -U__ANDROID__ -D__TRUSTY__ -std=c++17

# Add support for nanopb tag numbers > 255 and fields larger than 255 bytes or
# 255 array entries.
MODULE_COMPILEFLAGS += -DPB_FIELD_16BIT
# STATIC_ASSERT in pb.h might conflict with STATIC_ASSEET in compiler.h
MODULE_COMPILEFLAGS += -DPB_NO_STATIC_ASSERT

include make/trusted_app.mk
