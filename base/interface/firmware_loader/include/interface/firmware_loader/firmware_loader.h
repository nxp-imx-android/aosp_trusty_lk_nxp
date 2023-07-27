/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <lk/compiler.h>
#include <stdint.h>

__BEGIN_CDECLS

#define FIRMWARELOADER_PORT "com.android.trusty.firmwareloader"

enum firmware_loader_command : uint32_t {
    FIRMLOADER_REQ_SHIFT = 1,
    FIRMLOADER_RESP_BIT = 1,

    FIRMLOADER_CMD_LOAD_FIRMWARE = (0 << FIRMLOADER_REQ_SHIFT),
};

enum firmware_loader_error : uint32_t {
    FIRMWARELOADER_NO_ERROR = 0,
    FIRMWARELOADER_ERR_UNKNOWN_CMD,
    FIRMWARELOADER_ERR_INVALID_CMD,
    FIRMWARELOADER_ERR_NO_MEMORY,
    FIRMWARELOADER_ERR_VERIFICATION_FAILED,
    FIRMWARELOADER_ERR_LOADING_FAILED,
    FIRMWARELOADER_ERR_ALREADY_EXISTS,
    FIRMWARELOADER_ERR_INTERNAL,
    FIRMWARELOADER_ERR_INVALID_VERSION,
    FIRMWARELOADER_ERR_POLICY_VIOLATION,
    FIRMWARELOADER_ERR_NOT_ENCRYPTED,
};

/**
 * firmware_loader_header - Serial header for communicating with firmware_loader
 * @cmd: the command; one of &enum firmware_loader_command values.
 */
struct firmware_loader_header {
    uint32_t cmd;
} __PACKED;

/**
 * firmware_loader_load_app_req - Serial arguments for LOAD_FIRMWAREN command
 * @package_size: size of the firmware package.
 *
 * Load an firmware from a given memory region. The request message also
 * contains a handle for a dmabuf that contains the firmware package.
 *
 * The response is a &struct firmware_loader_resp with the error code or
 * %FIRMWARELOADER_NO_ERROR on success.
 */
struct firmware_loader_load_firm_req {
    uint64_t package_size;
} __PACKED;

/**
 * firmware_loader_resp - Common header for all firmwareloader responses
 * @hdr - header with command value.
 * @error - error code returned by peer; one of &enum firmwareloader_error values.
 *
 * This structure is followed by the response-specific payload, if the command
 * has one.
 */
struct firmware_loader_resp {
    struct firmware_loader_header hdr;
    uint32_t error;
} __PACKED;

__END_CDECLS
