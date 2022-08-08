/*
 * Copyright (C) 2017 The Android Open Source Project
 * Copyright 2017 NXP
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

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uapi/err.h>

#include <interface/hwkey/hwkey.h>
#include <nxp_hwcrypto_uuid_consts.h>
#include <openssl/aes.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>

#include "caam.h"
#include "common.h"
#include "hwkey_keyslots.h"
#include "hwkey_srv_priv.h"
#include <lib/storage/storage.h>

#define TLOG_TAG "hwkey_caam"
#include <trusty_log.h>

static uint8_t skeymod[16] __attribute__((aligned(16))) = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

static uint8_t skeymod_hbk[16] __attribute__((aligned(16))) = {
        0x3b, 0xe9, 0x75, 0x28, 0xc4, 0x3a, 0x6d, 0x52,
        0x42, 0x9c, 0x24, 0x1e, 0x07, 0xb0, 0x43, 0x1e};

/*
 *  Manufacture Protection Public Key support
 */
#define MPPUB_KEY_SIZE 64
#define MPPUB_KEY_ID "com.android.trusty.keymaster.mppubk"
static const uuid_t km_uuid = KEYMASTER_SERVER_APP_UUID;

/*
 * BKEK used as HBK
 */
#define HBK_KEY_SIZE 32
#define HBK_KEY_ID "com.android.trusty.keymaster.hbk"

/*
 * BKEK used as HUK
 */
#define HUK_KEY_SIZE 32
#define HUK_KEY_ID "com.android.trusty.storage_auth.huk"

/*
 * KAK (Key Agreement Key)
 */
#define KM_KAK_SIZE 32
#define KM_KAK_ID "com.android.trusty.keymint.kak"

/*
 *  RPMB Key support
 */
#define RPMB_SS_AUTH_KEY_SIZE 32
#define RPMB_SS_AUTH_KEY_ID "com.android.trusty.storage_auth.rpmb"

/*
 *  Widevine keybox
 */
#define HWOEMCRYPTO_WV_KEYBOX_ID "com.android.trusty.hwoemcrypto.wvkeybox"
static const uuid_t wv_uuid = HWOEMCRYPTO_SERVER_APP_UUID;

static uint8_t kdfv1_key[32] __attribute__((aligned(32)));
// TODO replace this key as shared key
static uint8_t shared_key[32] __attribute__((aligned(32)));

// TODO read this version from bootloader rollback index
#define TRUSTY_COMMITTED_ROLLBACK_VERSION 0

uint32_t mp_dec(uint8_t* enc, size_t size, uint8_t* out) {
    DECLARE_SG_SAFE_BUF(mppk, 64);
    caam_gen_mppubk((uint32_t)(intptr_t)mppk);

    caam_aes_op(mppk, 16, enc, out, size, false);

    return 0;
}

/*
 * Derive key V1 - HKDF based key derive.
 */
uint32_t derive_key_v1(const uuid_t* uuid,
                       const uint8_t* ikm_data,
                       size_t ikm_len,
                       uint8_t* key_buf,
                       size_t key_len) {
    if (!ikm_len)
        return HWKEY_ERR_BAD_LEN;

    if (!HKDF(key_buf, key_len, EVP_sha256(), (const uint8_t*)kdfv1_key,
              sizeof(kdfv1_key), (const uint8_t*)uuid, sizeof(uuid_t), ikm_data,
              ikm_len)) {
        TLOGE("HDKF failed 0x%x\n", ERR_get_error());
        memset(key_buf, 0, key_len);
        return HWKEY_ERR_GENERIC;
    }

    return HWKEY_NO_ERROR;
}

/*
 * Context labels for key derivation contexts, see derive_key_versioned_v1() for
 * details.
 */
#define HWKEY_DERIVE_VERSIONED_CONTEXT_LABEL "DERIVE VERSIONED"
#define ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL "TZOS"

#define HWKEY_DERIVE_VERSIONED_SALT "hwkey derive versioned salt"

static uint8_t context_buf[4096];

/**
 * fill_context_buf() - Add data to context_buf
 * @src: Pointer to data to copy into the context buf. If null, @len zero bytes
 *       will be added.
 * @len: Number of bytes of data to add.
 * @cur_position: Pointer to the next unwritten byte of context_buf. Updated
 *                with the new current position when successful.
 *
 * Return: HWKEY_NO_ERROR on success, HWKEY_ERR_BAD_LEN if @len will cause the
 * buffer to overflow.
 */
static uint32_t fill_context_buf(const void* src,
                                 size_t len,
                                 size_t* cur_position) {
    size_t new_position;
    if (len == 0) {
        return HWKEY_NO_ERROR;
    }
    if (__builtin_add_overflow(*cur_position, len, &new_position) ||
        new_position >= sizeof(context_buf)) {
        return HWKEY_ERR_BAD_LEN;
    }
    if (src == NULL) {
        memset(&context_buf[*cur_position], 0, len);
    } else {
        memcpy(&context_buf[*cur_position], src, len);
    }
    *cur_position = new_position;
    return HWKEY_NO_ERROR;
}

/*
 * In a real implementation this portion of the derivation should be done by a
 * trusted source of the Trusty OS rollback version. Doing the key derivation
 * here in the hwkey service protects against some app-level compromises, but
 * does not protect against compromise of any Trusty code that can derive
 * directly using the secret key derivation input - which in this sample
 * implementation would be the kernel and the hwkey service.
 *
 * This function MUST mix @rollback_version_source, @os_rollback_version, and
 * @hwkey_context into the derivation context in a way that the client cannot
 * forge.
 */
static uint32_t root_of_trust_derive_key(bool shared,
                                         uint32_t rollback_version_source,
                                         int32_t os_rollback_version,
                                         const uint8_t* hwkey_context,
                                         size_t hwkey_context_len,
                                         uint8_t* key_buf,
                                         size_t key_len) {
    size_t context_len = 0;
    int rc;
    const size_t root_of_trust_context_len =
            sizeof(ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL) +
            sizeof(rollback_version_source) + sizeof(os_rollback_version);
    const uint8_t* secret_key;
    size_t secret_key_len;
    size_t total_len;

    /*
     * We need to move the hwkey_context (currently at the beginning of
     * context_buf) over to make room for the root-of-trust context injected
     * before it. We avoid the need for a separate buffer by memmoving it first
     * then adding the context into the space we made.
     */
    if (__builtin_add_overflow(hwkey_context_len, root_of_trust_context_len,
                               &total_len) ||
        total_len >= sizeof(context_buf)) {
        return HWKEY_ERR_BAD_LEN;
    }
    memmove(&context_buf[root_of_trust_context_len], hwkey_context,
            hwkey_context_len);

    /*
     * Add a fixed label to ensure that another user of the same key derivation
     * primitive will not collide with this use, regardless of the provided
     * hwkey_context (as long as other users also add a different fixed label).
     */
    rc = fill_context_buf(ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL,
                          sizeof(ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL),
                          &context_len);
    if (rc) {
        return rc;
    }
    /* Keys for different version limit sources must be different */
    rc = fill_context_buf(&rollback_version_source,
                          sizeof(rollback_version_source), &context_len);
    if (rc) {
        return rc;
    }
    /*
     * Keys with different rollback versions must not be the same. This is part
     * of the root-of-trust context to ensure that a compromised kernel cannot
     * forge a version (if the root of trust is outside of Trusty)
     */
    rc = fill_context_buf(&os_rollback_version, sizeof(os_rollback_version),
                          &context_len);
    if (rc) {
        return rc;
    }

    assert(root_of_trust_context_len == context_len);

    /*
     * We already moved the hwkey_context into place after the root of trust
     * context.
     */
    context_len += hwkey_context_len;

    if (shared) {
        secret_key = shared_key;
        secret_key_len = sizeof(shared_key);
    } else {
        secret_key = kdfv1_key;
        secret_key_len = sizeof(kdfv1_key);
    }

    if (!HKDF(key_buf, key_len, EVP_sha256(), secret_key, secret_key_len,
              (const uint8_t*)HWKEY_DERIVE_VERSIONED_SALT,
              sizeof(HWKEY_DERIVE_VERSIONED_SALT), context_buf, context_len)) {
        TLOGE("HDKF failed 0x%x\n", ERR_get_error());
        memset(key_buf, 0, key_len);
        return HWKEY_ERR_GENERIC;
    }
    return HWKEY_NO_ERROR;
}

int32_t get_current_os_rollback_version(uint32_t source) {
    switch (source) {
    case HWKEY_ROLLBACK_RUNNING_VERSION:
        return TRUSTY_RUNNING_ROLLBACK_VERSION;

    case HWKEY_ROLLBACK_COMMITTED_VERSION:
        return TRUSTY_COMMITTED_ROLLBACK_VERSION;

    default:
        TLOGE("Unknown rollback version source: %u\n", source);
        return ERR_NOT_VALID;
    }
}

/*
 * Derive a versioned key - HMAC SHA256 based versioned key derivation function
 */
uint32_t derive_key_versioned_v1(
        const uuid_t* uuid,
        bool shared,
        uint32_t rollback_version_source,
        int32_t rollback_versions[HWKEY_ROLLBACK_VERSION_INDEX_COUNT],
        const uint8_t* user_context,
        size_t user_context_len,
        uint8_t* key_buf,
        size_t key_len) {
    size_t context_len = 0;
    int i;
    uint32_t rc = HWKEY_NO_ERROR;
    int32_t os_rollback_version =
            rollback_versions[HWKEY_ROLLBACK_VERSION_OS_INDEX];
    int32_t os_rollback_version_current =
            get_current_os_rollback_version(rollback_version_source);

    if (os_rollback_version_current < 0) {
        rc = HWKEY_ERR_NOT_VALID;
        goto err;
    }

    if (os_rollback_version > os_rollback_version_current) {
        TLOGE("Requested rollback version too new: %u\n", os_rollback_version);
        rc = HWKEY_ERR_NOT_FOUND;
        goto err;
    }

    /* short-circuit derivation if we have nothing to derive */
    if (key_len == 0) {
        rc = HWKEY_NO_ERROR;
        goto err;
    }

    /* for compatibility with unversioned derive, require a context */
    if (!key_buf || !user_context || user_context_len == 0) {
        rc = HWKEY_ERR_NOT_VALID;
        goto err;
    }

    /*
     * This portion of the context may always be added by the hwkey service, as
     * it deals with the identity of the client requesting the key derivation.
     */
    /*
     * Fixed label ensures that this derivation will not collide with a
     * different user of root_of_trust_derive_key(), regardless of the provided
     * user context (as long as other users also add a different fixed label).
     */
    rc = fill_context_buf(HWKEY_DERIVE_VERSIONED_CONTEXT_LABEL,
                          sizeof(HWKEY_DERIVE_VERSIONED_CONTEXT_LABEL),
                          &context_len);
    if (rc) {
        goto err;
    }
    /* Keys for different apps must be different */
    rc = fill_context_buf(uuid, sizeof(*uuid), &context_len);
    if (rc) {
        goto err;
    }
    for (i = 0; i < HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT; ++i) {
        /*
         * We skip the OS version because the root-of-trust should be inserting
         * that, and we don't want to mask a buggy implementation there in
         * testing. If the root-of-trust somehow did not insert the OS version,
         * we want to notice.
         */
        if (i == HWKEY_ROLLBACK_VERSION_OS_INDEX) {
            continue;
        }
        rc = fill_context_buf(&rollback_versions[i], sizeof(*rollback_versions),
                              &context_len);
        if (rc) {
            goto err;
        }
    }
    /* Reserve space for additional versions in the future */
    if (HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT <
        HWKEY_ROLLBACK_VERSION_INDEX_COUNT) {
        rc = fill_context_buf(NULL,
                              sizeof(*rollback_versions) *
                                      (HWKEY_ROLLBACK_VERSION_INDEX_COUNT -
                                       HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT),
                              &context_len);
        if (rc) {
            goto err;
        }
    }
    /*
     * Clients need to be able to generate multiple different keys in the same
     * app.
     */
    rc = fill_context_buf(user_context, user_context_len, &context_len);
    if (rc) {
        goto err;
    }

    rc = root_of_trust_derive_key(shared, rollback_version_source,
                                  os_rollback_version, context_buf, context_len,
                                  key_buf, key_len);
    if (rc) {
        goto err;
    }

err:
    memset(context_buf, 0, sizeof(context_buf));
    return rc;
}
/* Secure storage service app uuid */
static const uuid_t ss_uuid = SECURE_STORAGE_SERVER_APP_UUID;
static size_t rpmb_keyblob_len;
static uint8_t rpmb_keyblob[RPMBKEY_LEN];
static bool rpmb_keyslot_valid = true;

/*
 * Fetch RPMB Secure Storage Authentication key
 */
static uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot* slot,
                                     uint8_t* kbuf,
                                     size_t kbuf_len,
                                     size_t* klen) {
#ifdef SOFTWARE_CRYPTO
    memset(kbuf, 0, RPMB_SS_AUTH_KEY_SIZE);
    *klen = RPMB_SS_AUTH_KEY_SIZE;
    return HWKEY_NO_ERROR;
#else
    uint32_t res;
    assert(kbuf_len >= RPMB_SS_AUTH_KEY_SIZE);

    /* Get the rpmb key from keyslot if it's valid, otherwise return huk */
    if (rpmb_keyslot_valid) {
        if (rpmb_keyblob_len != sizeof(rpmb_keyblob))
            return HWKEY_ERR_NOT_FOUND; /* no RPMB key */

        res = caam_decap_blob(skeymod, sizeof(skeymod), kbuf, rpmb_keyblob,
                              RPMB_SS_AUTH_KEY_SIZE);
        if (res == CAAM_SUCCESS)
            *klen = RPMB_SS_AUTH_KEY_SIZE;
        else {
            /* wipe target buffer */
            TLOGE("%s: failed to unpack rpmb key\n", __func__);
            goto fail;
        }
    } else {
        res = caam_gen_bkek_key(skeymod, sizeof(skeymod),
                                (uint32_t)(intptr_t)kbuf, HUK_KEY_SIZE);
        if (res == CAAM_SUCCESS)
            *klen = HUK_KEY_SIZE;
        else {
            TLOGE("%s: failed to generate huk!\n", __func__);
            goto fail;
        }
    }

    return HWKEY_NO_ERROR;

fail:
    memset(kbuf, 0, RPMB_SS_AUTH_KEY_SIZE);
    return HWKEY_ERR_GENERIC;

#endif
}

/*
 * Fetch manufacture production key
 */
static uint32_t get_mppub_key(const struct hwkey_keyslot* slot,
                                     uint8_t* kbuf,
                                     size_t kbuf_len,
                                     size_t* klen) {
    uint32_t res;
    assert(kbuf_len >= MPPUB_KEY_SIZE);

    res = caam_gen_mppubk((uint32_t)(intptr_t)kbuf);

    if (res == CAAM_SUCCESS) {
        *klen = MPPUB_KEY_SIZE;
        return HWKEY_NO_ERROR;
    } else {
        /* wipe target buffer */
        TLOGE("%s: failed to generate mppub key!\n", __func__);
        memset(kbuf, 0, MPPUB_KEY_SIZE);
        return HWKEY_ERR_GENERIC;
    }
}

/*
 * Derive the bkek as HBK
 */
static uint32_t get_hbk_key(const struct hwkey_keyslot* slot,
                            uint8_t* kbuf,
                            size_t kbuf_len,
                            size_t* klen) {
    uint32_t res;
    assert(kbuf_len >= HBK_KEY_SIZE);

    res = caam_gen_bkek_key(skeymod_hbk, sizeof(skeymod_hbk), (uint32_t)(intptr_t)kbuf, HBK_KEY_SIZE);

    if (res == CAAM_SUCCESS) {
        *klen = HBK_KEY_SIZE;
        return HWKEY_NO_ERROR;
    } else {
        /* wipe target buffer */
        TLOGE("%s: failed to generate hbk!\n", __func__);
        memset(kbuf, 0, HBK_KEY_SIZE);
        return HWKEY_ERR_GENERIC;
    }
}

/*
 * Derive the bkek as HUK
 */
static uint32_t get_huk_key(const struct hwkey_keyslot* slot,
                            uint8_t* kbuf,
                            size_t kbuf_len,
                            size_t* klen) {
    uint32_t res;
    assert(kbuf_len >= HUK_KEY_SIZE);

    res = caam_gen_bkek_key(skeymod, sizeof(skeymod), (uint32_t)(intptr_t)kbuf, HUK_KEY_SIZE);

    if (res == CAAM_SUCCESS) {
        *klen = HUK_KEY_SIZE;
        return HWKEY_NO_ERROR;
    } else {
        /* wipe target buffer */
        TLOGE("%s: failed to generate huk!\n", __func__);
        memset(kbuf, 0, HUK_KEY_SIZE);
        return HWKEY_ERR_GENERIC;
    }
}

static uint32_t get_kak_key(const struct hwkey_keyslot* slot,
                            uint8_t* kbuf,
                            size_t kbuf_len,
                            size_t* klen) {
    assert(kbuf);
    assert(klen);
    memset(kbuf, 0, KM_KAK_SIZE);

    if (kbuf_len < KM_KAK_SIZE) {
        return HWKEY_ERR_BAD_LEN;
    }
    memcpy(kbuf, shared_key, KM_KAK_SIZE);
    *klen = KM_KAK_SIZE;

    return HWKEY_NO_ERROR;
}

/*
 * Load the wv keybox form secure storage
 */
static const char* WvKeyBoxFilename = "wv.keybox";
static uint32_t get_wv_key(const struct hwkey_keyslot* slot,
                            uint8_t* kbuf,
                            size_t kbuf_len,
                            size_t* klen) {
    storage_session_t session;
    file_handle_t file_handle;
    int rc = 0;

    /* connect to secure storage TA */
    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("hwkey: failed to connect to storage TA!\n");
        goto fail;
    }

    /* open file in secure storage */
    rc = storage_open_file(session, &file_handle, WvKeyBoxFilename, STORAGE_FILE_OPEN_CREATE, 0);
    if (rc < 0) {
        TLOGE("hwkey: failed to open keybox!\n");
        storage_close_session(session);
        goto fail;
    }

    /* read the keybox */
    rc = storage_read(file_handle, 0, kbuf, kbuf_len);
    storage_close_file(file_handle);
    storage_close_session(session);

fail:
    if (rc <= 0) {
        TLOGE("hwkey: keybox read failed!\n");
        return HWKEY_ERR_GENERIC;
    } else {
        TLOGE("hwkey: keybox read successfully!\n");
        *klen = rc;
        return HWKEY_NO_ERROR;
    }
}

/*
 * Apploader key(s)
 */
struct apploader_key {
    const uint8_t* key_data;

    // Pointer to the symbol holding the size of the key.
    // This needs to be a pointer because the size is not a
    // constant known to the compiler at compile time,
    // so it cannot be used to initialize the field directly.
    const unsigned int* key_size_ptr;
};

#define INCLUDE_APPLOADER_KEY(key, key_file)   \
    INCFILE(key##_data, key##_size, key_file); \
    static struct apploader_key key = {        \
            .key_data = key##_data,            \
            .key_size_ptr = &key##_size,       \
    };

#undef APPLOADER_HAS_SIGNING_KEYS
#undef APPLOADER_HAS_ENCRYPTION_KEYS

#ifdef APPLOADER_SIGN_PUBLIC_KEY_0_FILE
INCLUDE_APPLOADER_KEY(apploader_sign_key_0, APPLOADER_SIGN_PUBLIC_KEY_0_FILE);
#define APPLOADER_SIGN_KEY_0 "com.android.trusty.apploader.sign.key.0"
#define APPLOADER_HAS_SIGNING_KEYS
#endif

#ifdef APPLOADER_SIGN_PUBLIC_KEY_1_FILE
INCLUDE_APPLOADER_KEY(apploader_sign_key_1, APPLOADER_SIGN_PUBLIC_KEY_1_FILE);
#define APPLOADER_SIGN_KEY_1 "com.android.trusty.apploader.sign.key.1"
#define APPLOADER_HAS_SIGNING_KEYS
#endif

#ifdef APPLOADER_ENCRYPT_KEY_0_FILE
INCLUDE_APPLOADER_KEY(apploader_encrypt_key_0, APPLOADER_ENCRYPT_KEY_0_FILE);
#define APPLOADER_ENCRYPT_KEY_0 "com.android.trusty.apploader.encrypt.key.0"
#define APPLOADER_HAS_ENCRYPTION_KEYS
#endif

#ifdef APPLOADER_ENCRYPT_KEY_1_FILE
INCLUDE_APPLOADER_KEY(apploader_encrypt_key_1, APPLOADER_ENCRYPT_KEY_1_FILE);
#define APPLOADER_ENCRYPT_KEY_1 "com.android.trusty.apploader.encrypt.key.1"
#define APPLOADER_HAS_ENCRYPTION_KEYS
#endif

#if defined(APPLOADER_HAS_SIGNING_KEYS) || \
        defined(APPLOADER_HAS_ENCRYPTION_KEYS)
/* Apploader app uuid */
static const uuid_t apploader_uuid = APPLOADER_APP_UUID;

static uint32_t get_apploader_key(const struct apploader_key* key,
                                  uint8_t* kbuf,
                                  size_t kbuf_len,
                                  size_t* klen) {
    assert(kbuf);
    assert(klen);
    assert(key);
    assert(key->key_size_ptr);

    size_t key_size = (size_t)*key->key_size_ptr;
    assert(kbuf_len >= key_size);

    memcpy(kbuf, key->key_data, key_size);
    *klen = key_size;

    return HWKEY_NO_ERROR;
}
#endif

#ifdef APPLOADER_HAS_SIGNING_KEYS
static uint32_t get_apploader_sign_key(const struct hwkey_keyslot* slot,
                                       uint8_t* kbuf,
                                       size_t kbuf_len,
                                       size_t* klen) {
    assert(slot);
    return get_apploader_key(slot->priv, kbuf, kbuf_len, klen);
}
#endif

#ifdef APPLOADER_HAS_ENCRYPTION_KEYS

static const uuid_t hwaes_uuid = HWAES_APP_UUID;

static const uuid_t* apploader_allowed_opaque_key_uuids[] = {
        &hwaes_uuid,
};

/* Adapter to cast hwkey_opaque_handle_data.priv to struct apploader_key* */
static uint32_t get_apploader_key_opaque(
        const struct hwkey_opaque_handle_data* data,
        uint8_t* kbuf,
        size_t kbuf_len,
        size_t* klen) {
    assert(data);
    return get_apploader_key(data->priv, kbuf, kbuf_len, klen);
}

#ifdef APPLOADER_ENCRYPT_KEY_0
static struct hwkey_opaque_handle_data
        apploader_encrypt_key_0_opaque_handle_data = {
                .allowed_uuids = apploader_allowed_opaque_key_uuids,
                .allowed_uuids_len =
                        countof(apploader_allowed_opaque_key_uuids),
                .retriever = get_apploader_key_opaque,
                .priv = &apploader_encrypt_key_0,
};
#endif

#ifdef APPLOADER_ENCRYPT_KEY_1
static struct hwkey_opaque_handle_data
        apploader_encrypt_key_1_opaque_handle_data = {
                .allowed_uuids = apploader_allowed_opaque_key_uuids,
                .allowed_uuids_len =
                        countof(apploader_allowed_opaque_key_uuids),
                .retriever = get_apploader_key_opaque,
                .priv = &apploader_encrypt_key_1,
};
#endif

#endif

/*
 *  List of keys slots that hwkey service supports
 */
static const struct hwkey_keyslot _keys[] = {
        {
                .uuid = &ss_uuid,
                .key_id = RPMB_SS_AUTH_KEY_ID,
                .handler = get_rpmb_ss_auth_key,
        },
        {
                .uuid = &km_uuid,
                .key_id = MPPUB_KEY_ID,
                .handler = get_mppub_key,
        },
        {
                .uuid = &km_uuid,
                .key_id = HBK_KEY_ID,
                .handler = get_hbk_key,
        },
        {
                .uuid = &km_uuid,
                .key_id = KM_KAK_ID,
                .handler = get_kak_key,
        },
        {
                .uuid = &ss_uuid,
                .key_id = HUK_KEY_ID,
                .handler = get_huk_key,
        },
        {
                .uuid = &wv_uuid,
                .key_id = HWOEMCRYPTO_WV_KEYBOX_ID,
                .handler = get_wv_key,
        },
#ifdef APPLOADER_SIGN_KEY_0
        {
                .uuid = &apploader_uuid,
                .key_id = APPLOADER_SIGN_KEY_0,
                .handler = get_apploader_sign_key,
                .priv = &apploader_sign_key_0,
        },
#endif
#ifdef APPLOADER_SIGN_KEY_1
        {
                .uuid = &apploader_uuid,
                .key_id = APPLOADER_SIGN_KEY_1,
                .handler = get_apploader_sign_key,
                .priv = &apploader_sign_key_1,
        },
#endif
#ifdef APPLOADER_ENCRYPT_KEY_0
        {
                .uuid = &apploader_uuid,
                .key_id = APPLOADER_ENCRYPT_KEY_0,
                .handler = get_key_handle,
                .priv = &apploader_encrypt_key_0_opaque_handle_data,
        },
#endif
#ifdef APPLOADER_ENCRYPT_KEY_1
        {
                .uuid = &apploader_uuid,
                .key_id = APPLOADER_ENCRYPT_KEY_1,
                .handler = get_key_handle,
                .priv = &apploader_encrypt_key_1_opaque_handle_data,
        },
#endif
};

static void unpack_kbox(void) {
    struct keyslot_package* kbox = malloc(sizeof(struct keyslot_package));

    caam_get_keybox(kbox);
    if (strncmp(kbox->magic, KEYPACK_MAGIC, 4)) {
        rpmb_keyslot_valid = false;
    } else {
        /* Copy RPMB blob */
        assert(!rpmb_keyblob_len); /* key should be unset */
        if (kbox->rpmb_keyblob_len != sizeof(rpmb_keyblob)) {
            TLOGE("Unexpected RPMB key len: %u\n", kbox->rpmb_keyblob_len);
            rpmb_keyslot_valid = false;
        } else {
            memcpy(rpmb_keyblob, kbox->rpmb_keyblob, kbox->rpmb_keyblob_len);
            rpmb_keyblob_len = kbox->rpmb_keyblob_len;
        }
    }

    if (kbox != NULL)
        free(kbox);
}

/*
 *  Initialize Fake HWKEY service provider
 */
void hwkey_init_srv_provider(void) {
    int rc;
#ifndef SOFTWARE_CRYPTO

    TLOGD("Init HWKEY service provider\n");

    /* generate kdfv1 root, it should never fail */
    rc = caam_gen_kdfv1_root_key(kdfv1_key, sizeof(kdfv1_key));
    if (rc != CAAM_SUCCESS) {
        TLOGE("Generate kdfv1 fail!\n");
        abort();
    }

    rc = caam_gen_bkek_key(skeymod_hbk, sizeof(skeymod_hbk),
                          (uint32_t)(intptr_t)shared_key, sizeof(shared_key));
    if (rc != CAAM_SUCCESS) {
        TLOGE("Generate shared key fail!\n");
        abort();
    }

    unpack_kbox();

#endif
    /* install key handlers */
    hwkey_install_keys(_keys, countof(_keys));

    /* start service */
    rc = hwkey_start_service();
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to start HWKEY service\n", rc);
    }
}
