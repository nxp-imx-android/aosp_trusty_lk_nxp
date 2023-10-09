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

//#define TLOG_LVL 5
#define TLOG_TAG "trusty_matter"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <matter_messages.h>
#include <trusty_matter.h>
#include <trusty_log.h>
#include <secure_storage_manager.h>
#include <utils.h>

namespace matter {

using namespace std;

const char* MatterCertDAC = "MatterCertDAC";
const char* MatterCertPAI = "MatterCertPAI";
const char* MatterCertCD  = "MatterCertCD";
const char* MatterDACPrivateKey  = "MatterDACPrivateKey";
const char* MatterDACPublicKey   = "MatterDACPublicKey";
const char* MatterOperationKeyPair = "MatterOperationKeyPair";

matter_error_t TrustyMatter::OPKeyInitialize() {
    matter_error_t error = MATTER_ERROR_OK;

    TLOGD("%s: In OPKeyInitialize.\n", __func__);

    opkeypair.reset(new (std::nothrow) OpKeyPair);
    if (!(opkeypair.get())) {
        TLOGE("%s: failed to allocate memory for OPKeyPair!\n", __func__);
        return MATTER_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        TLOGE("%s: failed to get secure storage instance!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    Buffer opkey = ss_manager->ReadCertFromStorage(MatterOperationKeyPair, &error);
    if ((error != MATTER_ERROR_OK) || (opkey.buffer_size() != sizeof(OpKeyPair)) || \
        memcmp(opkey.begin(), MATTER_FABRIC_MAIGC, sizeof(MATTER_FABRIC_MAIGC))) {
        TLOGE("%s:OPKeyPair is invalid, reinitializing...\n", __func__);
        memset(opkeypair.get(), 0, sizeof(OpKeyPair));
        memcpy(opkeypair->magic, MATTER_FABRIC_MAIGC, sizeof(MATTER_FABRIC_MAIGC));
        // update the keypair into secure storage
        error = ss_manager->WriteCertToStorage(MatterOperationKeyPair,
                                               (const uint8_t *)(opkeypair.get()), sizeof(OpKeyPair));
    } else {
        // we get a valid OpKeyPair from secure storage
        memcpy((uint8_t *)(opkeypair.get()), opkey.begin(), sizeof(OpKeyPair));
        error = MATTER_ERROR_OK;
    }

    return error;
}

void TrustyMatter::ImportCert(const ImportCertRequest &request,
                              ImportCertResponse *response, const char* name) {
    if (response == nullptr)
        return;

    TLOGD("%s: In ImportCert, name:%s\n", __func__, name);

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    const uint8_t *cert = request.cert_data.begin();
    size_t cert_size = request.cert_data.buffer_size();
    if (cert_size == 0) {
        response->error = MATTER_ERROR_INVALID_INPUT_LENGTH;
        return;
    }

    response->error = ss_manager->WriteCertToStorage(name, cert, cert_size);
}

void TrustyMatter::ExportCert(const ExportCertRequest &request, ExportCertResponse *response, const char* name) {
    if (response == nullptr)
        return;

    TLOGD("%s: In ExportCert, name:%s\n", __func__, name);

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->error = MATTER_ERROR_OK;
    response->cert_data = ss_manager->ReadCertFromStorage(name, &response->error);
}

void TrustyMatter::ImportDACCert(const ImportCertRequest& request,
                             ImportCertResponse* response) {
    ImportCert(request, response, MatterCertDAC);
}

void TrustyMatter::ExportDACCert(const ExportCertRequest& request,
                             ExportCertResponse* response) {
    ExportCert(request, response, MatterCertDAC);
}

void TrustyMatter::ImportPAICert(const ImportCertRequest& request,
                             ImportCertResponse* response) {
    ImportCert(request, response, MatterCertPAI);
}

void TrustyMatter::ExportPAICert(const ExportCertRequest& request,
                             ExportCertResponse* response) {
    ExportCert(request, response, MatterCertPAI);
}

void TrustyMatter::ImportCDCert(const ImportCertRequest& request,
                             ImportCertResponse* response) {
    ImportCert(request, response, MatterCertCD);
}

void TrustyMatter::ExportCDCert(const ExportCertRequest& request,
                             ExportCertResponse* response) {
    ExportCert(request, response, MatterCertCD);
}

void TrustyMatter::ImportDACPubKey(const ImportCertRequest& request,
                             ImportCertResponse* response) {
    ImportCert(request, response, MatterDACPublicKey);
}

void TrustyMatter::ImportDACPriKey(const ImportCertRequest& request,
                             ImportCertResponse* response) {
    ImportCert(request, response, MatterDACPrivateKey);
}

void TrustyMatter::SignWithDACKey(const SignWithDAKeyRequest &request,
                                 SignWithDAKeyResponse* response) {
    const uint8_t *msg = nullptr;
    size_t msg_size  = 0;
    uint8_t digest[kSHA256_Hash_Length];
    uint8_t sig[kP256_ECDSA_Signature_Length_Raw];
    int ret = 0;

    TLOGD("%s: In SignWithDACKey.\n", __func__);

    /* load DA Keys */
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    Buffer private_key = ss_manager->ReadCertFromStorage(MatterDACPrivateKey, &response->error);
    if (response->error != MATTER_ERROR_OK) {
        TLOGE("%s: failed to load DAC private key!\n", __func__);
        return;
    }
    if (private_key.buffer_size() != kP256_PrivateKey_Length) {
        TLOGE("%s: wrong DAC private key size!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    /* Get the sha256 digest of the msg */
    msg = request.msg.begin();
    msg_size = request.msg.buffer_size();
    memset(&digest[0], 0, sizeof(digest));
    SHA256(msg, msg_size, digest);

    UniquePtr<P256Keypair> p256_keypair(new (std::nothrow) P256Keypair);
    /* import keys */
    ret = p256_keypair->Deserialize(nullptr, 0, private_key.begin(), kP256_PrivateKey_Length);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }
    /* sign message */
    ret = p256_keypair->ECSignMsg(digest, kSHA256_Hash_Length, sig);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->sig.Reinitialize(sig, kP256_ECDSA_Signature_Length_Raw);
    response->error = MATTER_ERROR_OK;;
}

void TrustyMatter::P256KeypairInitialize(const P256KPInitializeRequest& request,
                             P256KPInitializeResponse* response) {
    uint64_t handler = 0;
    P256Keypair *p256_keypair = nullptr;
    int ret = 0;
    uint8_t pubkey[kP256_PublicKey_Length];

    TLOGD("%s: In P256KeypairInitialize, fabric:%d\n", __func__, request.fabric_index);

    // get valid P256KeyPair instance
    handler = request.p256_handler;
    if (handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("P256KeypairInitialize: get valid handle, use it!\n");
        p256_keypair = p256_keypair_table.Find(handler);
        if (p256_keypair == nullptr) {
            TLOGE("can't find keypair instance!\n");
            response->p256_handler = 0;
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        // no valid p256 instance exist, create a new one.
        UniquePtr<P256Keypair> p256_keypair_(new (std::nothrow) P256Keypair);
        p256_keypair = p256_keypair_.get();
        while (handler == 0) {
        // we must make sure the random handler is not 0
            RAND_bytes((uint8_t *)&handler, sizeof(handler));
        };
        p256_keypair->handler = handler;
        p256_keypair_table.Add(std::move(p256_keypair_));
    }
    response->p256_handler = handler;

    p256_keypair->fabric_index = request.fabric_index;
    ret = p256_keypair->Initialize(pubkey);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        response->p256_handler = 0;
        return;
    }

    response->public_key.Reinitialize(pubkey, kP256_PublicKey_Length);
    response->error = MATTER_ERROR_OK;
}

void TrustyMatter::P256KeypairSerialize(const P256KPSerializeRequest& request,
                             P256KPSerializeResponse* response) {
    uint64_t handler = 0;
    P256Keypair *p256_keypair = nullptr;
    int ret = 0;
    uint8_t prikey[kP256_PrivateKey_Length];

    TLOGD("%s: In P256KeypairSerialize.\n", __func__);

    handler = request.p256_handler;
    if (handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("P256KeypairSerialize: get valid handle, use it!\n");
        p256_keypair = p256_keypair_table.Find(handler);
        if (p256_keypair == nullptr) {
            TLOGE("can't find keypair instance!\n");
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        TLOGE("Get invalid p256 handler: %lu!\n", handler);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    if (IsValidFabricIndex(p256_keypair->fabric_index)) {
        TLOGE("%s: can not export OPKeyPair!\n", __func__);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    ret = p256_keypair->Serialize(prikey);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->private_key.Reinitialize(prikey, kP256_PrivateKey_Length);
    response->error = MATTER_ERROR_OK;
}

void TrustyMatter::P256KeypairDeserialize(const P256KPDeserializeRequest& request,
                             P256KPDeserializeResponse* response) {
    uint64_t handler = 0;
    P256Keypair *p256_keypair = nullptr;
    const uint8_t *pubkey = nullptr, *prikey = nullptr;
    size_t pubkey_size = 0, prikey_size = 0;
    int ret = 0;

    TLOGD("%s: In P256KeypairDeserialize.\n", __func__);

    handler = request.p256_handler;
    if (handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("P256KeypairDeserialize: get valid handle, use it!\n");
        p256_keypair = p256_keypair_table.Find(handler);
        if (p256_keypair == nullptr) {
            TLOGE("can't find keypair instance!\n");
            response->p256_handler = 0;
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        // no valid p256 instance exist, create a new one.
        UniquePtr<P256Keypair> p256_keypair_(new (std::nothrow) P256Keypair);
        p256_keypair = p256_keypair_.get();
        while (handler == 0) {
            // we must make sure the random handler is not 0
            RAND_bytes((uint8_t *)&handler, sizeof(handler));
        };
        p256_keypair->handler = handler;
        p256_keypair_table.Add(std::move(p256_keypair_));
    }
    response->p256_handler = handler;

    // now we get the right instance, do the Deserialize
    pubkey = request.public_key.begin();
    pubkey_size = request.public_key.buffer_size();
    prikey = request.private_key.begin();
    prikey_size = request.private_key.buffer_size();
    ret = p256_keypair->Deserialize(pubkey, pubkey_size, prikey, prikey_size);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        response->p256_handler = 0;
        return;
    }

    response->error = MATTER_ERROR_OK;
}

void TrustyMatter::P256KeypairDestory(const P256KPDestoryRequest& request,
                             P256KPDestoryResponse* response) {
    uint64_t handler = 0;

    handler = request.p256_handler;
    if (handler != 0) {
        TLOGD("P256KeypairDestory: get valid handle %lu, use it!\n", handler);
        p256_keypair_table.Delete(handler);
    } else {
        TLOGD("Destory: Get invalid p256 handler: %lu!\n", handler);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    response->error = MATTER_ERROR_OK;
}

void TrustyMatter::P256KeypairECSignMsg(const P256KPECSignMsgRequest& request,
                             P256KPECSignMsgResponse* response) {
    P256Keypair *p256_keypair = nullptr;
    uint8_t sig[kP256_ECDSA_Signature_Length_Raw];
    uint64_t handler = 0;
    int ret = 0;

    TLOGD("%s: In P256KeypairECSignMsg.\n", __func__);

    handler = request.p256_handler;
    if (handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("P256KeypairECSignMsg: get valid handle: %lu, use it!\n", handler);
        p256_keypair = p256_keypair_table.Find(handler);
        if (p256_keypair == nullptr) {
            TLOGE("can't find keypair instance!\n");
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        TLOGE("P256KeypairECSignMsg: Get invalid p256 handler: %lu!\n", handler);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    const uint8_t *hash256 = request.hash256.begin();
    size_t hash256_size = request.hash256.buffer_size();
    ret = p256_keypair->ECSignMsg(hash256, hash256_size, sig);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->sig.Reinitialize(sig, kP256_ECDSA_Signature_Length_Raw);
    response->error = MATTER_ERROR_OK;
}

void TrustyMatter::P256KeypairNewCSR(const P256KPNewCSRRequest& request,
                                     P256KPNewCSRResponse* response) {
    P256Keypair *p256_keypair = nullptr;
    uint64_t handler = 0;
    uint8_t *out_csr = nullptr;
    int csr_length = 0;
    int ret = 0;

    TLOGD("%s: In P256KeypairNewCSR.\n", __func__);

    handler = request.p256_handler;
    if (handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("P256KeypairNewCSR: get valid handle: %lu, use it!\n", handler);
        p256_keypair = p256_keypair_table.Find(handler);
        if (p256_keypair == nullptr) {
            TLOGE("can't find keypair instance!\n");
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        TLOGE("P256KeypairNewCSR: Get invalid p256 handler: %lu!\n", handler);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    ret = p256_keypair->NewCSR(&out_csr, csr_length);
    if ((ret != 0) || (out_csr == nullptr)) {
        TLOGE("P256KeypairNewCSR: generate p256 CSR failed! ret:%d.\n", ret);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        if (out_csr != nullptr)
            free(out_csr);
        return;
    }

    response->error = MATTER_ERROR_OK;
    response->csr.Reinitialize(out_csr, csr_length);
    free(out_csr);
}

void TrustyMatter::P256KeypairECDH_Derive_secret(const P256KPECDHDeriveSecretRequest& request,
                                   P256KPECDHDeriveSecretResponse* response) {
    P256Keypair *p256_keypair = nullptr;
    uint64_t handler = 0;
    uint8_t *secret = nullptr;
    const uint8_t *remote_pubkey = nullptr;
    size_t secret_size = 0;
    int ret = 0;

    TLOGD("%s: In P256KeypairECDH_Derive_secret.\n", __func__);

    handler = request.p256_handler;
    if (handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("P256KeypairECDH_Derive_secret: get valid handle: %lu, use it!\n", handler);
        p256_keypair = p256_keypair_table.Find(handler);
        if (p256_keypair == nullptr) {
            TLOGE("can't find keypair instance!\n");
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        TLOGE("P256KeypairECDH_Derive_secret: Get invalid p256 handler: %lu!\n", handler);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    if (request.remote_pubkey.buffer_size() != kP256_PublicKey_Length) {
        TLOGE("P256KeypairECDH_Derive_secret: wrong remote public key size: %lu!\n", request.remote_pubkey.buffer_size());
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    remote_pubkey = request.remote_pubkey.begin();
    ret = p256_keypair->ECDH_Derive_Secret(remote_pubkey, &secret, secret_size);
    if ((ret != 0) || (secret == nullptr)) {
        TLOGE("P256KeypairECDH_Derive_secret: derive secret failed! ret:%d.\n", ret);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        if (secret != nullptr)
            free(secret);
        return;
    }

    response->error = MATTER_ERROR_OK;
    response->secret.Reinitialize(secret, secret_size);
    free(secret);
}

void TrustyMatter::HasOpKeypairForFabric(const HasOpKeypairForFabricRequest& request,
                                         HasOpKeypairForFabricResponse* response) {
    int index = 0;
    uint8_t fabric_index;

    fabric_index = request.fabric_index;
    if (!IsValidFabricIndex(fabric_index)) {
        TLOGE("%s: Invalid fabric index!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    TLOGD("%s: In HasOpKeypairForFabric, fabric: %d \n", __func__, fabric_index);

    // check the stored operational keypair
    if (!(opkeypair.get()) || \
        memcmp(opkeypair->magic, MATTER_FABRIC_MAIGC, sizeof(MATTER_FABRIC_MAIGC))) {
        TLOGE("%s: operational keypair struct is not well initialized!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    // try to find one
    for (index = 0; index < MATTER_MAX_FABRIC_SLOT; index++) {
        if (opkeypair->slot[index].FabricIndex == fabric_index) {
            response->keypair_exist = true;
            break;
        }
    }

    if (index == MATTER_MAX_FABRIC_SLOT)
        response->keypair_exist = false;

    response->error = MATTER_ERROR_OK;
}

void TrustyMatter::CommitOpKeypairForFabric(const CommitOpKeypairForFabricRequest& request,
                                            CommitOpKeypairForFabricResponse* response) {
    int ret = 0, index = 0;
    uint8_t fabric_index;
    uint64_t p256_handler;
    P256Keypair *p256_keypair = nullptr;
    uint8_t prikey[kP256_PrivateKey_Length];

    fabric_index = request.fabric_index;
    p256_handler = request.p256_handler;
    if (!IsValidFabricIndex(fabric_index)) {
        TLOGE("%s: Invalid fabric index!\n", __func__);
        response->error = MATTER_ERROR_INVALID_FABRIC_ID;
        return;
    }

    TLOGD("%s: In CommitOpKeypairForFabric, fabric: %d\n", __func__, fabric_index);

    if (p256_handler != 0) {
        // we already get a valid instance, use it directly.
        TLOGD("%s: get valid handle, use it!\n", __func__);
        p256_keypair = p256_keypair_table.Find(p256_handler);
        if (p256_keypair == nullptr) {
            TLOGE("%s: can't find keypair instance!\n", __func__);
            response->error = MATTER_ERROR_INVALID_ARGUMENT;
            return;
        }
    } else {
        TLOGE("%s: Get invalid p256 handler: %lu!\n", __func__, p256_handler);
        response->error = MATTER_ERROR_INVALID_ARGUMENT;
        return;
    }

    // get the private key
    ret = p256_keypair->Serialize(prikey);
    if (ret != 0) {
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    // first, we check if the same fabricIndex alreay exist
    for (index = 0; index < MATTER_MAX_FABRIC_SLOT; index++) {
        if (opkeypair->slot[index].FabricIndex == fabric_index)
            break;
    }
    if (index == MATTER_MAX_FABRIC_SLOT) {
        TLOGD("%s: No overriding fabricIndex: %d\n", __func__, fabric_index);
        // second, let's find an empty slot
        for (index = 0; index < MATTER_MAX_FABRIC_SLOT; index++) {
            if (opkeypair->slot[index].FabricIndex == kUndefinedFabricIndex)
                break;
        }
        if (index == MATTER_MAX_FABRIC_SLOT) {
            TLOGE("%s: No available OpKeyPair slot!\n", __func__);
            response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
            return;
        }
    }

    // we should get a suitable slot when we get here
    opkeypair->slot[index].FabricIndex = fabric_index;
    memcpy(opkeypair->slot[index].PrivateKey, prikey, kP256_PrivateKey_Length);

    // update the keyslot to secure storage
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        TLOGE("%s: failed to get secure storage instance!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }
    response->error = ss_manager->WriteCertToStorage(MatterOperationKeyPair,
                                                     (const uint8_t *)opkeypair.get(), sizeof(OpKeyPair));
}

void TrustyMatter::RemoveOpKeypairForFabric(const RemoveOpKeypairForFabricRequest& request,
                                            RemoveOpKeypairForFabricResponse* response) {
    int index = 0;
    uint8_t fabric_index;

    fabric_index = request.fabric_index;
    if (!IsValidFabricIndex(fabric_index)) {
        TLOGE("%s: Invalid fabric index!\n", __func__);
        response->error = MATTER_ERROR_INVALID_FABRIC_ID;
        return;
    }

    TLOGD("%s: In RemoveOpKeypairForFabric, fabric: %d\n", __func__, fabric_index);

    // the keypair should already in memory, let's find it
    for (index = 0; index < MATTER_MAX_FABRIC_SLOT; index++) {
        if (opkeypair->slot[index].FabricIndex == fabric_index) {
            // bingo!
            opkeypair->slot[index].FabricIndex = kUndefinedFabricIndex;
            memset(opkeypair->slot[index].PrivateKey, 0, kP256_PrivateKey_Length);
            break;
        }
    }
    if (index == MATTER_MAX_FABRIC_SLOT) {
        TLOGE("%s: can't find operation keypair corresponding to fabric: %d!\n", __func__, fabric_index);
        response->error = MATTER_ERROR_INVALID_FABRIC_ID;
        return;
    }

    // update the keypair to secure storage
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        TLOGE("%s: failed to get secure storage instance!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }
    response->error = ss_manager->WriteCertToStorage(MatterOperationKeyPair,
                                                     (const uint8_t *)opkeypair.get(), sizeof(OpKeyPair));
}

void TrustyMatter::SignWithStoredOpKey(const SignWithStoredOpKeyRequest& request,
                                       SignWithStoredOpKeyResponse* response) {
    int index = 0, ret = 0;
    uint8_t fabric_index;
    const uint8_t *msg = nullptr;
    size_t msg_size  = 0;
    uint8_t prikey[kP256_PrivateKey_Length];
    uint8_t digest[kSHA256_Hash_Length];
    uint8_t sig[kP256_ECDSA_Signature_Length_Raw];

    fabric_index = request.fabric_index;
    if (!IsValidFabricIndex(fabric_index)) {
        TLOGE("%s: Invalid fabric index!\n", __func__);
        response->error = MATTER_ERROR_INVALID_FABRIC_ID;
        return;
    }

    TLOGD("%s: In SignWithStoredOpKey, fabric: %d\n", __func__, fabric_index);

    // the keypair should already in memory, let's find it
    for (index = 0; index < MATTER_MAX_FABRIC_SLOT; index++) {
        if (opkeypair->slot[index].FabricIndex == fabric_index) {
            // bingo!
            memcpy(prikey, opkeypair->slot[index].PrivateKey, kP256_PrivateKey_Length);
            break;
        }
    }
    if (index == MATTER_MAX_FABRIC_SLOT) {
        TLOGE("%s: can't find operation keypair corresponding to fabric: %d!\n", __func__, fabric_index);
        response->error = MATTER_ERROR_INVALID_FABRIC_ID;
        return;
    }

    /* Get the sha256 digest of the msg */
    msg = request.msg.begin();
    msg_size = request.msg.buffer_size();
    memset(&digest[0], 0, sizeof(digest));
    SHA256(msg, msg_size, digest);

    UniquePtr<P256Keypair> p256_keypair(new (std::nothrow) P256Keypair);
    /* import keys */
    ret = p256_keypair->Deserialize(nullptr, 0, prikey, kP256_PrivateKey_Length);
    if (ret != 0) {
        TLOGE("%s: failed to import key!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }
    /* sign message */
    ret = p256_keypair->ECSignMsg(digest, kSHA256_Hash_Length, sig);
    if (ret != 0) {
        TLOGE("%s: failed to sign message!\n", __func__);
        response->error = MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->sig.Reinitialize(sig, kP256_ECDSA_Signature_Length_Raw);
    response->error = MATTER_ERROR_OK;;
}

} // namespace matter
