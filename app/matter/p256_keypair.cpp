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

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <p256_keypair.h>

#define TLOG_TAG "P256KeyPair"
#define TLOG_LVL 3

#include <trusty_log.h>

namespace matter {

constexpr size_t kP256_PublicKey_Length  = 65;
constexpr size_t kP256_PrivateKey_Length = 32;
constexpr size_t kP256_FE_Length         = 32;

int P256Keypair::Initialize(uint8_t *pubkey) {
    int result = 0;
    int nid = 0;
    int rc = 0;
    const EC_POINT *pubkey_ecp = nullptr;
    EC_GROUP * group = nullptr;
    size_t pubkey_size = 0;

    TLOGD("Trusty: Initialize!\n");
    // clear old keys
    if (ec_key != nullptr) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }

    nid = EC_curve_nist2nid("P-256"); //only p-256 are supported.
    ec_key = EC_KEY_new_by_curve_name(nid);
    if (ec_key == nullptr) {
        TLOGE("Initialize: failed in EC_KEY_new_by_curve_name()!\n");
        rc = -1;
        goto ret;
    }

    result = EC_KEY_generate_key(ec_key);
    if (result != 1) {
        TLOGE("Initialize: failed in EC_KEY_generate_key()!\n");
        rc = -1;
        goto ret;
    }

    // next get public key
    pubkey_ecp = EC_KEY_get0_public_key(ec_key);
    if (pubkey_ecp == nullptr) {
        TLOGE("Initialize: failed in EC_KEY_get0_public_key()!\n");
        rc = -1;
        goto ret;
    }

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == nullptr) {
        TLOGE("Initialize: failed in EC_GROUP_new_by_curve_name()!\n");
        rc = -1;
        goto ret;
    }

    pubkey_size = EC_POINT_point2oct(group, pubkey_ecp, POINT_CONVERSION_UNCOMPRESSED, pubkey, kP256_PublicKey_Length, nullptr);
    if (pubkey_size != kP256_PublicKey_Length) {
        TLOGE("Initialize: failed in EC_POINT_point2oct()!\n");
        rc = -1;
        goto ret;
    }
    pubkey_ecp = nullptr;

ret:
    if (group != nullptr) {
        EC_GROUP_free(group);
        group = nullptr;
    }

    return rc;
}

int P256Keypair::Serialize(uint8_t *prikey) {
    int privkey_size = 0;

    TLOGD("Trusty: Serialize!\n");

    if (ec_key == nullptr) {
        TLOGE("Serialize: ec_key is not initialized!\n");
        return -1;
    }

    const BIGNUM * privkey_bn = EC_KEY_get0_private_key(ec_key);
    if (privkey_bn == nullptr) {
        TLOGE("Serialize: failed in EC_KEY_get0_private_key()!\n");
        return -1;
    }

    privkey_size = BN_bn2binpad(privkey_bn, prikey, kP256_PrivateKey_Length);
    privkey_bn   = nullptr;
    if (privkey_size != kP256_PrivateKey_Length) {
        TLOGE("Serialize: failed to get private key!\n");
        return -1;
    }

    return 0;
}

int P256Keypair::Deserialize(const uint8_t *pubkey, size_t pubkey_size, const uint8_t *prikey, size_t prikey_size) {
    BIGNUM * pvt_key = nullptr;
    EC_GROUP * group     = nullptr;
    EC_POINT * key_point = nullptr;
    int result = 0;
    int nid = 0;
    int rc = 0;

    TLOGD("Trusty: Deserialize!\n");
    // clear old keys
    if (ec_key != nullptr) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }

    //sanity check the keys
    if ((pubkey != nullptr) && (pubkey_size != kP256_PublicKey_Length)) {
        TLOGE("%s: wrong public key!\n", __func__);
        return -1;
    }
    if ((prikey == nullptr) || (prikey_size != kP256_PrivateKey_Length)) {
        TLOGE("%s: wrong private key!\n", __func__);
        return -1;
    }

    nid = EC_curve_nist2nid("P-256"); //only p-256 are supported.
    ec_key = EC_KEY_new_by_curve_name(nid);
    if (ec_key == nullptr) {
        TLOGE("failed in EC_KEY_new_by_curve_name()!\n");
        rc = -1;
        goto ret;
    }
    if (pubkey != nullptr) {
        group = EC_GROUP_new_by_curve_name(nid);
        if (group == nullptr) {
            TLOGE("failed in EC_GROUP_new_by_curve_name()!\n");
            rc = -1;
            goto ret;
        }
        key_point = EC_POINT_new(group);
        if (key_point == nullptr) {
            TLOGE("failed in EC_POINT_new()!\n");
            rc = -1;
            goto ret;
        }
        result = EC_POINT_oct2point(group, key_point, pubkey, pubkey_size, nullptr);
        if (result != 1) {
            TLOGE("failed in EC_POINT_oct2point()!\n");
            rc = -1;
            goto ret;
        }
        result = EC_KEY_set_public_key(ec_key, key_point);
        if (result != 1) {
            TLOGE("failed in EC_KEY_set_public_key()!\n");
            rc = -1;
            goto ret;
        }
    }
    pvt_key = BN_bin2bn(prikey, prikey_size, nullptr);
    if (pvt_key == nullptr) {
        TLOGE("failed in BN_bin2bn()!\n");
        rc = -1;
        goto ret;
    }
    result = EC_KEY_set_private_key(ec_key, pvt_key);
    if (result != 1) {
        TLOGE("failed in EC_KEY_set_private_key()!\n");
        rc = -1;
        goto ret;
    }

ret:
    if (group != nullptr) {
        EC_GROUP_free(group);
        group = nullptr;
    }

    if (pvt_key != nullptr) {
        BN_free(pvt_key);
        pvt_key = nullptr;
    }

    if (key_point != nullptr) {
        EC_POINT_free(key_point);
        key_point = nullptr;
    }

    return rc;
}

int P256Keypair::ECSignMsg(const uint8_t *hash256, size_t hash256_size, uint8_t *sig) {
    const BIGNUM * r = nullptr;
    const BIGNUM * s = nullptr;
    ECDSA_SIG * result  = nullptr;
    int rc = 0;

    TLOGD("Trusty: ECSignMsg!\n");
    result = ECDSA_do_sign(hash256, hash256_size, ec_key);
    if (result == nullptr) {
        TLOGE("ECSignMsg: failed in ECDSA_do_sign()!\n");
        rc = -1;
        goto ret;
    }

    ECDSA_SIG_get0(result, &r, &s);
    if ((r == nullptr) || (s == nullptr) ||
        (BN_num_bytes(r) > kP256_FE_Length) || (BN_num_bytes(s) > kP256_FE_Length)) {
        TLOGE("ECSignMsg: failed in ECDSA_SIG_get0()!\n");
        rc = -1;
        goto ret;
    }

    if (BN_bn2binpad(r, sig, kP256_FE_Length) != kP256_FE_Length) {
        TLOGE("ECSignMsg: convert r failed!\n");
        rc = -1;
        goto ret;
    }

    if (BN_bn2binpad(s, sig + kP256_FE_Length, kP256_FE_Length) != kP256_FE_Length) {
        TLOGE("ECSignMsg: convert s failed!\n");
        rc = -1;
        goto ret;
    }

ret:
    if (result != nullptr)
        ECDSA_SIG_free(result);

    return rc;
}

int P256Keypair::NewCSR(uint8_t **out_csr, int &csr_length) {
    X509_REQ *x509_req = nullptr;
    EVP_PKEY *evp_pkey = nullptr;
    X509_NAME *subject = nullptr;
    uint8_t *csr = nullptr;
    int csr_length_local = 0;
    int result = 0;
    int rc = 0;

    TLOGD("Trusty: NewCSR!\n");
    x509_req = X509_REQ_new();
    if (x509_req == nullptr) {
        TLOGE("NewCSR: X509_REQ_new() failed!\n");
        rc = -1;
        goto ret;
    }

    subject = X509_NAME_new();
    if (subject == nullptr) {
        TLOGE("NewCSR: X509_NAME_new() failed!\n");
        rc = -1;
        goto ret;
    }

    result = X509_REQ_set_version(x509_req, 0);
    if (result != 1) {
        TLOGE("NewCSR: X509_REQ_set_version() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EC_KEY_check_key(ec_key);
    if (result != 1) {
        TLOGE("NewCSR: EC_KEY_check_key() failed!\n");
        rc = -1;
        goto ret;
    }

    evp_pkey = EVP_PKEY_new();
    if (evp_pkey == nullptr) {
        TLOGE("NewCSR: EVP_PKEY_new() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key);
    if (result != 1) {
        TLOGE("NewCSR: EVP_PKEY_set1_EC_KEY() failed!\n");
        rc = -1;
        goto ret;
    }

    result = X509_REQ_set_pubkey(x509_req, evp_pkey);
    if (result != 1) {
        TLOGE("NewCSR: X509_REQ_set_pubkey() failed!\n");
        rc = -1;
        goto ret;
    }

    result = X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, reinterpret_cast<const uint8_t *>("CSR"), -1, -1, 0);
    if (result != 1) {
        TLOGE("NewCSR: X509_NAME_add_entry_by_txt() failed!\n");
        rc = -1;
        goto ret;
    }

    result = X509_REQ_set_subject_name(x509_req, subject);
    if (result != 1) {
        TLOGE("NewCSR: X509_REQ_set_subject_name() failed!\n");
        rc = -1;
        goto ret;
    }

    result = X509_REQ_sign(x509_req, evp_pkey, EVP_sha256());
    if (result <= 0) {
        TLOGE("NewCSR: X509_REQ_sign() failed!\n");
        rc = -1;
        goto ret;
    }

    csr_length_local = i2d_X509_REQ(x509_req, nullptr);
    if (csr_length_local <= 0) {
        TLOGE("NewCSR: get csr length failed!\n");
        rc = -1;
        goto ret;
    } else {
        csr = (uint8_t *)malloc(csr_length_local);
        if (csr == nullptr) {
            TLOGE("NewCSR: failed to allocate memory!\n");
            rc = -1;
            goto ret;
        }
        *out_csr = csr;
        csr_length = i2d_X509_REQ(x509_req, &csr);
    }

ret:
    if (evp_pkey != nullptr)
        EVP_PKEY_free(evp_pkey);

    if (subject != nullptr)
        X509_NAME_free(subject);

    if (x509_req != nullptr)
        X509_REQ_free(x509_req);

    return rc;
}

int P256Keypair::ECDH_Derive_Secret(const uint8_t *remote_pubkey, uint8_t **secret, size_t &secret_size) {
    EVP_PKEY *local_key  = nullptr;
    EVP_PKEY *remote_key = nullptr;
    EVP_PKEY_CTX *context = nullptr;
    EC_KEY *ec_key_tmp = nullptr;
    EC_GROUP * group = nullptr;
    EC_POINT * point = nullptr;
    int result = -1;
    int rc = 0;
    int nid = 0;

    TLOGD("Trusty: ECDH_Derive_Secret!\n");
    EC_KEY *ec_key_ = EC_KEY_dup(ec_key);
    if (ec_key_ == nullptr) {
        TLOGE("ECDH_Derive_Secret: EC_KEY_dup() failed!\n");
        rc = -1;
        goto ret;
    }

    local_key = EVP_PKEY_new();
    if (local_key == nullptr) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_new() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_set1_EC_KEY(local_key, ec_key_);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_set1_EC_KEY() failed!\n");
        rc = -1;
        goto ret;
    }

    nid = EC_curve_nist2nid("P-256"); //only p-256 are supported.
    ec_key_tmp = EC_KEY_new_by_curve_name(nid);
    if (ec_key_tmp == nullptr) {
        TLOGE("ECDH_Derive_Secret: EC_KEY_new_by_curve_name() failed!\n");
        rc = -1;
        goto ret;
    }

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == nullptr) {
        TLOGE("ECDH_Derive_Secret: EC_GROUP_new_by_curve_name() failed!\n");
        rc = -1;
        goto ret;
    }

    point = EC_POINT_new(group);
    if (point == nullptr) {
        TLOGE("ECDH_Derive_Secret: EC_POINT_new() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EC_POINT_oct2point(group, point, remote_pubkey, kP256_PublicKey_Length, nullptr);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: EC_POINT_oct2point() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EC_KEY_set_public_key(ec_key_tmp, point);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: EC_KEY_set_public_key() failed!\n");
        rc = -1;
        goto ret;
    }

    remote_key = EVP_PKEY_new();
    if (remote_key == nullptr) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_new() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_set1_EC_KEY(remote_key, ec_key_tmp);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_set1_EC_KEY() failed!\n");
        rc = -1;
        goto ret;
    }

    context = EVP_PKEY_CTX_new(local_key, nullptr);
    if (context == nullptr) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_CTX_new() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_derive_init(context);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_derive_init() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_derive_set_peer(context, remote_key);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: EVP_PKEY_derive_set_peer() failed!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_derive(context, nullptr, &secret_size);
    if ((result != 1) || (secret_size <= 0)) {
        TLOGE("ECDH_Derive_Secret: failed to get secret size!\n");
        rc = -1;
        goto ret;
    }

    *secret = (uint8_t *)malloc(secret_size);
    if (*secret == nullptr) {
        TLOGE("ECDH_Derive_Secret: failed to allocate memory!\n");
        rc = -1;
        goto ret;
    }

    result = EVP_PKEY_derive(context, *secret, &secret_size);
    if (result != 1) {
        TLOGE("ECDH_Derive_Secret: failed to derive shared secret!\n");
        rc = -1;
        goto ret;
    }

ret:
    if (ec_key_ != nullptr)
        EC_KEY_free(ec_key_);

    if (ec_key_tmp != nullptr)
        EC_KEY_free(ec_key_tmp);

    if (remote_key != nullptr)
        EVP_PKEY_free(remote_key);

    if (local_key != nullptr)
        EVP_PKEY_free(local_key);

    if (point != nullptr)
        EC_POINT_free(point);

    if (group != nullptr)
        EC_GROUP_free(group);

    if (context != nullptr)
        EVP_PKEY_CTX_free(context);

    return rc;
}

P256Keypair::~P256Keypair() {
    TLOGD("Trusty: P256Keypair deconstructor!\n");
    if (ec_key != nullptr) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }
}
} // namespace matter
