/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define TLOG_TAG "firmwareloader-package"

#include <assert.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <interface/firmware_loader/firmware_loader_package.h>
#include <interface/hwkey/hwkey.h>
#include <inttypes.h>
#include <lib/hwaes/hwaes.h>
#include <lib/hwkey/hwkey.h>
#include <lk/compiler.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>
#include <trusty/memref.h>
#include <trusty_log.h>
#include <uapi/err.h>
#include <optional>

#include "firmware_loader_package.h"
#include "cose.h"

/*
 * Maximum size of any key we could possibly get from hwkey.
 * If the latter returns a key larger than this, validation fails.
 * For now, 128 bytes should be enough since the firmware loader only
 * supports 256-bit (P-256) ECDSA signatures which only need
 * about 90 bytes for their public keys. If other curves or algorithms
 * e.g., P-521 or RSS, are supported by the firmware loader at a later time,
 * this value will need to increase.
 */
constexpr uint32_t kMaximumKeySize =
        std::max(128, HWKEY_OPAQUE_HANDLE_MAX_SIZE);

static std::tuple<std::unique_ptr<uint8_t[]>, size_t>
get_key(hwkey_session_t hwkey_session,
        std::string_view op,
        uint8_t key_id,
        const uint8_t** public_key,
        unsigned int* public_key_size) {
    std::string key_slot{"com.android.trusty.firmware_loader."};
    key_slot += op;
    key_slot += ".key.";
    key_slot += std::to_string(static_cast<unsigned>(key_id));

    uint32_t key_size = kMaximumKeySize;
    std::unique_ptr<uint8_t[]> result(new (std::nothrow) uint8_t[key_size]());
    if (!result) {
        TLOGE("Failed to allocate memory for key\n");
        return {};
    }

    uint8_t* key_bytes = (uint8_t*)malloc(key_size * sizeof(uint8_t));
    long rc = hwkey_get_keyslot_data(hwkey_session, key_slot.c_str(),
                                     key_bytes, &key_size);
    if (rc < 0) {
        TLOGE("Failed to get key %" PRIu8 " from hwkey (%ld)\n", key_id, rc);
        free(key_bytes);
        return {};
    }

    if (public_key !=  NULL) {
        *public_key = key_bytes;
        *public_key_size = key_size;
    }

    memcpy(result.get(), key_bytes, key_size);

    if (public_key == NULL)
        free(key_bytes);
    return {std::move(result), static_cast<size_t>(key_size)};
}

static std::optional<bool> get_cbor_bool(std::unique_ptr<cppbor::Item>& item) {
    auto* item_simple = item->asSimple();
    if (item_simple == nullptr) {
        return {};
    }

    auto* item_bool = item_simple->asBool();
    if (item_bool == nullptr) {
        return {};
    }

    return item_bool->value();
}

static bool hwaesDecryptAes128GcmInPlace(
        std::basic_string_view<uint8_t> key,
        std::basic_string_view<uint8_t> nonce,
        uint8_t* encryptedData,
        size_t encryptedDataSize,
        std::basic_string_view<uint8_t> additionalAuthenticatedData,
        size_t* outPlaintextSize) {
    assert(outPlaintextSize != nullptr);
    if (encryptedDataSize <= kAesGcmTagSize) {
        TLOGE("encryptedData too small\n");
        return false;
    }

    if (nonce.size() != kAesGcmIvSize) {
        TLOGE("nonce is not kAesGcmIvSize bytes, got %zu\n", nonce.size());
        return false;
    }

    size_t ciphertextSize = encryptedDataSize - kAesGcmTagSize;
    unsigned char* tag = encryptedData + ciphertextSize;

    struct hwcrypt_args cryptArgs = {};
    cryptArgs.key.data_ptr = key.data();
    cryptArgs.key.len = key.size();
    cryptArgs.iv.data_ptr = nonce.data();
    cryptArgs.iv.len = nonce.size();
    cryptArgs.aad.data_ptr = additionalAuthenticatedData.data();
    cryptArgs.aad.len = additionalAuthenticatedData.size();
    cryptArgs.tag_in.data_ptr = tag;
    cryptArgs.tag_in.len = kAesGcmTagSize;
    cryptArgs.text_in.data_ptr = encryptedData;
    cryptArgs.text_in.len = ciphertextSize;
    cryptArgs.text_out.data_ptr = encryptedData;
    cryptArgs.text_out.len = ciphertextSize;
    cryptArgs.key_type = HWAES_OPAQUE_HANDLE;
    cryptArgs.padding = HWAES_NO_PADDING;
    cryptArgs.mode = HWAES_GCM_MODE;

    hwaes_session_t sess;
    auto ret = hwaes_open(&sess);
    if (ret != NO_ERROR) {
        return false;
    }

    ret = hwaes_decrypt(sess, &cryptArgs);
    if (ret == NO_ERROR) {
        *outPlaintextSize = ciphertextSize;
    }
    hwaes_close(sess);

    return ret == NO_ERROR;
}

bool firmware_loader_parse_package_metadata(
        uint8_t* package_start,
        size_t package_size,
        struct firmware_loader_package_metadata* metadata) {
    /*
     * This lambda will store the signing key into metadata->publicKey, and
     * also return a separate copy (wrapped in a unique_ptr) that is consumed
     * by strictCheckEcDsaSignature.
     */

    long rc = hwkey_open();
    if (rc < 0) {
        TLOGE("Failed to connect to hwkey (%ld)\n", rc);
        return false;
    }

    hwkey_session_t hwkey_session = static_cast<hwkey_session_t>(rc);

    auto local_get_sign_key = [metadata, hwkey_session](int key_id) {
        return get_key(hwkey_session, "sign", key_id, &metadata->public_key, &metadata->public_key_size);
    };

    const uint8_t* unsigned_package_start;
    size_t unsigned_package_size;
    if (!strictCheckEcDsaSignature(package_start, package_size,
                                   local_get_sign_key, &unsigned_package_start,
                                   &unsigned_package_size)) {
        TLOGE("Package signature verification failed\n");
        return false;
    } else {
        TLOGD("package signature successfully\n");
    }

    auto [pkg_item, _, error] = cppbor::parseWithViews(unsigned_package_start,
                                                       unsigned_package_size);
    if (pkg_item == nullptr) {
        TLOGE("cppbor returned error: %s\n", error.c_str());
        return false;
    }

    if (pkg_item->semanticTagCount() != 1) {
        TLOGE("Invalid package semantic tag count, expected 1 got %zd\n",
              pkg_item->semanticTagCount());
        return false;
    }
    if (pkg_item->semanticTag() != FIRMWARELOADER_PACKAGE_CBOR_TAG_FIRM) {
        TLOGE("Invalid package semantic tag: %" PRIu64 "\n",
              pkg_item->semanticTag());
        return false;
    }

    auto* pkg_array = pkg_item->asArray();
    if (pkg_array == nullptr) {
        TLOGE("Expected CBOR array\n");
        return false;
    }
    if (pkg_array->size() == 0) {
        TLOGE("Application package array is empty\n");
        return false;
    }

    auto* version = pkg_array->get(0)->asUint();
    if (version == nullptr) {
        TLOGE("Invalid version field CBOR type, got: 0x%x\n",
              static_cast<int>(pkg_array->get(0)->type()));
        return false;
    }
    if (version->unsignedValue() != FIRMWARELOADER_PACKAGE_FORMAT_VERSION_CURRENT) {
        TLOGE("Invalid package version, expected %" PRIu64 " got %" PRIu64 "\n",
              FIRMWARELOADER_PACKAGE_FORMAT_VERSION_CURRENT,
              version->unsignedValue());
        return false;
    }

    if (pkg_array->size() != 4) {
        TLOGE("Invalid number of CBOR array elements: %zd\n",
              pkg_array->size());
        return false;
    }

    auto* headers = pkg_array->get(1)->asMap();
    if (headers == nullptr) {
        TLOGE("Invalid headers CBOR type, got: 0x%x\n",
              static_cast<int>(pkg_array->get(1)->type()));
        return false;
    }

    /* Read headers and reject packages with invalid header labels */
    metadata->elf_is_cose_encrypt = false;
    for (auto& [label_item, value_item] : *headers) {
        auto* label_uint = label_item->asUint();
        if (label_uint == nullptr) {
            TLOGE("Invalid header label CBOR type, got: 0x%x\n",
                  static_cast<int>(label_item->type()));
            return false;
        }

        auto label = label_uint->unsignedValue();
        switch (label) {
        case FIRMWARELOADER_PACKAGE_HEADER_LABEL_CONTENT_IS_COSE_ENCRYPT: {
            auto value_opt_bool = get_cbor_bool(value_item);
            if (!value_opt_bool.has_value()) {
                TLOGE("Invalid content_is_cose_encrypt CBOR type\n");
                return false;
            }

            metadata->elf_is_cose_encrypt = value_opt_bool.value();
            break;
        }

        default:
            TLOGE("Package headers contain invalid label: %" PRIu64 "\n",
                  label);
            return false;
        }
    }

    const uint8_t* elf_start;
    size_t elf_size;
    if (metadata->elf_is_cose_encrypt) {
        /*
         * get the encryption key handle but keep the hwkey connection open
         * until we've finished decrypting with it
         */
        auto get_encrypt_key_handle = [hwkey_session](uint8_t key_id) {
            return get_key(hwkey_session, "encrypt", key_id, NULL, NULL);
        };

        auto& cose_encrypt = pkg_array->get(2);
        bool success = coseDecryptAes128GcmKeyWrapInPlace(
                cose_encrypt, get_encrypt_key_handle, {}, false, &elf_start,
                &elf_size, hwaesDecryptAes128GcmInPlace);

        hwkey_close(hwkey_session);

        if (!success) {
            TLOGE("Failed to decrypt ELF file\n");
            return false;
        } else {
            TLOGD("decrypt elf file successfully\n");
        }
    } else {
        hwkey_close(hwkey_session);
        auto* elf = pkg_array->get(2)->asViewBstr();
        if (elf == nullptr) {
            TLOGE("Invalid ELF CBOR type, got: 0x%x\n",
                  static_cast<int>(pkg_array->get(2)->type()));
            return false;
        }

        elf_start = reinterpret_cast<const uint8_t*>(elf->view().data());
        elf_size = elf->view().size();
    }

    auto* manifest = pkg_array->get(3)->asViewBstr();
    if (manifest == nullptr) {
        TLOGE("Invalid manifest CBOR type, got: 0x%x\n",
              static_cast<int>(pkg_array->get(3)->type()));
        return false;
    }

    metadata->elf_start = elf_start;
    metadata->elf_size = elf_size;
    metadata->manifest_start = manifest->view().data();
    metadata->manifest_size = manifest->view().size();

    return true;
}
