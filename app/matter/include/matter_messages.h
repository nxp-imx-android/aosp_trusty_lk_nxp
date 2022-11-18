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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <string_view>
#include <vector>

#include <serializable.h>
#include <matter_defs.h>

namespace matter {

/**
 * All responses include an error value, and if the error is not MATTER_ERROR_OK, return no additional
 * data.
 */
struct MatterResponse : public Serializable {
    explicit MatterResponse()
        : error(MATTER_ERROR_UNKNOWN_ERROR) {}

    size_t SerializedSize() const override;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    virtual size_t NonErrorSerializedSize() const = 0;
    virtual uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const = 0;
    virtual bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) = 0;

    matter_error_t error;
};

// Abstract base for empty requests.
struct EmptyMatterRequest : public Serializable {
    explicit EmptyMatterRequest() {}

    size_t SerializedSize() const override { return 0; }
    uint8_t* Serialize(uint8_t* buf, const uint8_t*) const override { return buf; }
    bool Deserialize(const uint8_t**, const uint8_t*) override { return true; };
};

// Empty response.
struct EmptyMatterResponse : public MatterResponse {
    explicit EmptyMatterResponse() {}

    size_t NonErrorSerializedSize() const override { return 0; }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t*) const override { return buf; }
    bool NonErrorDeserialize(const uint8_t**, const uint8_t*) override { return true; }
};

struct ImportCertRequest : public Serializable {
    size_t SerializedSize() const override {
        return cert_data.SerializedSize();
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return cert_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return cert_data.Deserialize(buf_ptr, end);
    }

    Buffer cert_data;
};

using ImportCertResponse = EmptyMatterResponse;

using ExportCertRequest = EmptyMatterRequest;

struct ExportCertResponse : public MatterResponse {
    size_t NonErrorSerializedSize() const override { return cert_data.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override { return cert_data.Serialize(buf, end); }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override { return cert_data.Deserialize(buf_ptr, end); }

    Buffer cert_data;
};

struct SignWithDAKeyRequest : public Serializable {
    size_t SerializedSize() const override {
        return msg.SerializedSize();
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return msg.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return msg.Deserialize(buf_ptr, end);
    }

    Buffer msg;
};

struct SignWithDAKeyResponse : public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sig.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override { return sig.Serialize(buf, end); }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override { return sig.Deserialize(buf_ptr, end); }

    Buffer sig;
};

struct P256KPInitializeRequest: public Serializable {
    size_t SerializedSize() const override {
         return sizeof(uint64_t);
     }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return append_uint64_to_buf(buf, end, p256_handler);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler);
    }

    uint64_t p256_handler;
};

struct P256KPInitializeResponse: public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sizeof(uint64_t) + public_key.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        return public_key.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) && public_key.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer public_key;
};

struct P256KPSerializeRequest: public Serializable {
    size_t SerializedSize() const override {
         return sizeof(uint64_t);
     }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return append_uint64_to_buf(buf, end, p256_handler);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler);
    }

    uint64_t p256_handler;
};

struct P256KPSerializeResponse: public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sizeof(uint64_t) + private_key.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        return private_key.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) && private_key.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer private_key;
};

struct P256KPDeserializeRequest : public Serializable {
    size_t SerializedSize() const override {
         return sizeof(uint64_t) + public_key.SerializedSize() + private_key.SerializedSize();
     }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        buf = public_key.Serialize(buf, end);
        return private_key.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) &&
               public_key.Deserialize(buf_ptr, end) && private_key.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer public_key;
    Buffer private_key;
};

struct P256KPDeserializeResponse : public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sizeof(uint64_t); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override { return append_uint64_to_buf(buf, end, p256_handler); }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override { return copy_uint64_from_buf(buf_ptr, end, &p256_handler); }

    uint64_t p256_handler;
};

struct P256KPDestoryRequest : public Serializable {
    size_t SerializedSize() const override {
        return sizeof(uint64_t);;
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return append_uint64_to_buf(buf, end, p256_handler);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler);
    }

    uint64_t p256_handler;
};

using P256KPDestoryResponse = EmptyMatterResponse;

struct P256KPECSignMsgRequest: public Serializable {
    size_t SerializedSize() const override {
        return sizeof(uint64_t) + hash256.SerializedSize();
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        return hash256.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) && hash256.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer hash256;
};

struct P256KPECSignMsgResponse: public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sizeof(uint64_t) + sig.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        return sig.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) &&
        sig.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer sig;
};

struct P256KPNewCSRRequest: public Serializable {
    size_t SerializedSize() const override {
        return sizeof(uint64_t);
    }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return append_uint64_to_buf(buf, end, p256_handler);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler);
    }

    uint64_t p256_handler;
};

struct P256KPNewCSRResponse: public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sizeof(uint64_t) + csr.SerializedSize(); }
        uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        return csr.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) &&
        csr.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer csr;
};

struct P256KPECDHDeriveSecretRequest: public Serializable {
     size_t SerializedSize() const override {
         return sizeof(uint64_t) + remote_pubkey.SerializedSize();
     }
     uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
         buf = append_uint64_to_buf(buf, end, p256_handler);
         return remote_pubkey.Serialize(buf, end);
     }
     bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
         return copy_uint64_from_buf(buf_ptr, end, &p256_handler) && remote_pubkey.Deserialize(buf_ptr, end);
     }

     uint64_t p256_handler;
     Buffer remote_pubkey;
};

struct P256KPECDHDeriveSecretResponse: public MatterResponse {
    size_t NonErrorSerializedSize() const override { return sizeof(uint64_t) + secret.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, p256_handler);
        return secret.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint64_from_buf(buf_ptr, end, &p256_handler) &&
               secret.Deserialize(buf_ptr, end);
    }

    uint64_t p256_handler;
    Buffer secret;
};

}  // namespace matter
