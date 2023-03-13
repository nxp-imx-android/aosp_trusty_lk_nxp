/*
 * Copyright 2023 The Android Open Source Project
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

#ifndef __MATTER_IPC_H__
#define __MATTER_IPC_H__

#define MATTER_PORT_NAME "com.android.trusty.matter"
#define MATTER_MAX_MSG_SIZE 4096

constexpr uint32_t MATTER_RESP_BIT = 1;
constexpr uint32_t MATTER_STOP_BIT = 2;
constexpr uint32_t MATTER_REQ_SHIFT = 2;

enum matter_command: uint32_t {
    MATTER_IMPORT_DAC         = (0x1 << MATTER_REQ_SHIFT),
    MATTER_IMPORT_PAI         = (0x2 << MATTER_REQ_SHIFT),
    MATTER_IMPORT_CD          = (0x3 << MATTER_REQ_SHIFT),
    MATTER_IMPORT_DAC_PRIKEY  = (0x4 << MATTER_REQ_SHIFT),

    // userspace commands
    MATTER_EXPORT_DAC = (0x100 << MATTER_REQ_SHIFT),
    MATTER_EXPORT_PAI = (0x101 << MATTER_REQ_SHIFT),
    MATTER_EXPORT_CD  = (0x102 << MATTER_REQ_SHIFT),
    MATTER_SIGN_WITH_DAC_KEY = (0x103 << MATTER_REQ_SHIFT),

    // userspace crypto commands
    MATTER_P256_KEYPAIR_INITIALIZE               = (0x200 << MATTER_REQ_SHIFT),
    MATTER_P256_KEYPAIR_SERIALIZE                = (0x201 << MATTER_REQ_SHIFT),
    MATTER_P256_KEYPAIR_DESERIALIZE              = (0x202 << MATTER_REQ_SHIFT),
    MATTER_P256_KEYPAIR_DESTORY                  = (0x203 << MATTER_REQ_SHIFT),
    MATTER_P256_KEYPAIR_ECSIGNMSG                = (0x204 << MATTER_REQ_SHIFT),
    MATTER_P256_KEYPAIR_NEWCSR                   = (0x205 << MATTER_REQ_SHIFT),
    MATTER_P256_KEYPAIR_ECDH_DERIVE_SECRET       = (0x206 << MATTER_REQ_SHIFT),
    MATTER_HAS_OP_KEYPAIR_FOR_FABRIC             = (0x207 << MATTER_REQ_SHIFT),
    MATTER_COMMIT_OP_KEYPAIR_FOR_FABRIC          = (0x208 << MATTER_REQ_SHIFT),
    MATTER_REMOVE_OP_KEYPAIR_FOR_FABRIC          = (0x209 << MATTER_REQ_SHIFT),
    MATTER_SIGN_WITH_STORED_OPKEY                = (0x20a << MATTER_REQ_SHIFT),
};

struct matter_message {
    uint32_t cmd;
    uint8_t payload[0];
};
#endif /* __MATTER_IPC_H__ */
