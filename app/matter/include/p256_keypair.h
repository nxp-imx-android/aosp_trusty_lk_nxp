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

#pragma once

#include <openssl/ec.h>
#include <operation_table.h>

namespace matter {

class P256Keypair {
public:
    ~P256Keypair();

    int Initialize(uint8_t *pubkey);
    int Serialize(uint8_t *prikey);
    int Deserialize(const uint8_t *pubkey, size_t pubkey_size, const uint8_t *prikey, size_t prikey_size);
    int ECSignMsg(const uint8_t *hash256, size_t hash256_size, uint8_t *sig);
    int NewCSR(uint8_t **out_csr, int &csr_length);
    int ECDH_Derive_Secret(const uint8_t *remote_pubkey, uint8_t **secret, size_t &secret_size);

    uint64_t handler = 0;
    uint8_t fabric_index = 0;
private:
    EC_KEY *ec_key = nullptr;
};

typedef OperationTable<P256Keypair> P256Keypair_table;

} //namespace matter
