/*
 * Copyright 2023 The Android Open Source Project
 *
 * Copy 2023 NXP
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

#include <matter_messages.h>
#include <p256_keypair.h>

#define MATTER_FABRIC_MAIGC "TrustyMatter"
#define MATTER_MAX_FABRIC_SLOT 10
#define MATTER_MAX_P256_KEYPAIR 20

namespace matter {

constexpr size_t kP256_PublicKey_Length = 65;
constexpr size_t kP256_PrivateKey_Length = 32;
constexpr size_t kP256_ECDSA_Signature_Length_Raw = 64;
constexpr size_t kSHA256_Hash_Length = 32;

typedef struct OpKeyPairSlot {
    uint8_t FabricIndex;
    uint8_t PrivateKey[kP256_PrivateKey_Length];
} OpKeyPairSlot;

typedef struct OpKeyPair {
    char magic[16];
    OpKeyPairSlot slot[MATTER_MAX_FABRIC_SLOT];
} OpKeyPair;

class TrustyMatter {
public:
    matter_error_t OPKeyInitialize();

    void ImportDACCert(const ImportCertRequest &request, ImportCertResponse *response);
    void ExportDACCert(const ExportCertRequest& request, ExportCertResponse* response);
    void ImportPAICert(const ImportCertRequest &request, ImportCertResponse *response);
    void ExportPAICert(const ExportCertRequest& request, ExportCertResponse* response);
    void ImportCDCert(const ImportCertRequest &request, ImportCertResponse *response);
    void ExportCDCert(const ExportCertRequest& request, ExportCertResponse* response);
    void ImportDACPubKey(const ImportCertRequest& request, ImportCertResponse* response);
    void ImportDACPriKey(const ImportCertRequest& request, ImportCertResponse* response);
    void SignWithDACKey(const SignWithDAKeyRequest &requese, SignWithDAKeyResponse* response);
    void P256KeypairInitialize(const P256KPInitializeRequest& request, P256KPInitializeResponse* response);
    void P256KeypairSerialize(const P256KPSerializeRequest& request, P256KPSerializeResponse* response);
    void P256KeypairDeserialize(const P256KPDeserializeRequest& request, P256KPDeserializeResponse* response);
    void P256KeypairDestory(const P256KPDestoryRequest& request, P256KPDestoryResponse* response);
    void P256KeypairECSignMsg(const P256KPECSignMsgRequest& request, P256KPECSignMsgResponse* response);
    void P256KeypairNewCSR(const P256KPNewCSRRequest& request, P256KPNewCSRResponse* response);
    void P256KeypairECDH_Derive_secret(const P256KPECDHDeriveSecretRequest& request, P256KPECDHDeriveSecretResponse* response);
    void HasOpKeypairForFabric(const HasOpKeypairForFabricRequest& request, HasOpKeypairForFabricResponse* response);
    void CommitOpKeypairForFabric(const CommitOpKeypairForFabricRequest& request, CommitOpKeypairForFabricResponse* response);
    void RemoveOpKeypairForFabric(const RemoveOpKeypairForFabricRequest& request, RemoveOpKeypairForFabricResponse* response);
    void SignWithStoredOpKey(const SignWithStoredOpKeyRequest& request, SignWithStoredOpKeyResponse* response);

private:
    void ImportCert(const ImportCertRequest &request, ImportCertResponse *response, const char* name);
    void ExportCert(const ExportCertRequest &request, ExportCertResponse *response, const char* name);
    P256Keypair_table p256_keypair_table{MATTER_MAX_P256_KEYPAIR};
    UniquePtr<OpKeyPair> opkeypair = nullptr;
};

} // namespace matter
