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
namespace matter {

class TrustyMatter {

public:
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

private:
    void ImportCert(const ImportCertRequest &request, ImportCertResponse *response, const char* name);
    void ExportCert(const ExportCertRequest &request, ExportCertResponse *response, const char* name);
    P256Keypair_table p256_keypair_table{10}; //TODO Is 10 enough?
};

} // namespace matter
