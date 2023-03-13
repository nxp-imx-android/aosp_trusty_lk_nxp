/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Copyright 2023 NXP
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

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef enum {
    MATTER_ERROR_OK = 0,
    MATTER_ERROR_UNKNOWN_ERROR = -1,
    MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED = -2,
    MATTER_ERROR_INVALID_INPUT_LENGTH = -3,
    MATTER_ERROR_MEMORY_ALLOCATION_FAILED = -4,
    MATTER_ERROR_INVALID_ARGUMENT = -5,
    MATTER_ERROR_TOO_MANY_OPERATIONS = -6,
    MATTER_ERROR_OPERATION_CANCELLED = -7,
    MATTER_ERROR_UNIMPLEMENTED = -8,
    MATTER_ERROR_SECURE_HW_BUSY = -9,
    MATTER_ERROR_NO_ENOUGH_MEMORY = -10,
    MATTER_ERROR_INVALID_FABRIC_ID = -11,
} matter_error_t;

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
