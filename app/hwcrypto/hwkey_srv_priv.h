/*
 * Copyright (C) 2016-2017 The Android Open Source Project
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
#include <sys/types.h>
#include <interface/hwaes/hwaes.h>
#include <interface/hwkey/hwkey.h>
#include <uapi/trusty_uuid.h>

struct hwkey_keyslot {
    const char* key_id;
    const uuid_t* uuid;
    const void* priv;
    uint32_t (*handler)(const struct hwkey_keyslot* slot,
                        uint8_t* kbuf,
                        size_t kbuf_len,
                        size_t* klen);
};

#define HWKEY_OPAQUE_HANDLE_SIZE 32
STATIC_ASSERT(HWKEY_OPAQUE_HANDLE_SIZE <= HWKEY_OPAQUE_HANDLE_MAX_SIZE);

/**
 * struct hwkey_opaque_handle_data - Opaque handle data for keyslots that allow
 * opaque usage in hwaes.
 *
 * Intended for use in the @hwkey_keyslot.priv field. The retriever function is
 * equivalent to the generic &hwkey_keyslot->handler but is called only when a
 * service allowed to unwrap opaque requests this handle.
 *
 * @token:             The access token used as an opaque handle to
 *                     reference this keyslot
 * @allowed_uuids:     Array of UUIDs that are allowed to retrieve the
 *                     plaintext key corresponding to an opaque handle
 *                     for this slot
 * @allowed_uuids_len: Length of the @allowed_reader_uuids array
 * @priv:              Opaque pointer to keyslot-specific data
 * @retriever:         Keyslot-specific callback which retrieves the
 *                     actual key corresponding to this opaque handle.
 */
struct hwkey_opaque_handle_data {
    const uuid_t** allowed_uuids;
    size_t allowed_uuids_len;
    const void* priv;
    uint32_t (*retriever)(const struct hwkey_opaque_handle_data* data,
                          uint8_t* kbuf,
                          size_t kbuf_len,
                          size_t* klen);
};

__BEGIN_CDECLS

/**
 * get_key_handle() - Handler for opaque keys
 *
 * Create and return an access token for a key slot. This key slot must contain
 * a pointer to a &struct hwkey_opaque_handle_data in the &hwkey_keyslot.priv
 * field.
 */
uint32_t get_key_handle(const struct hwkey_keyslot* slot,
                        uint8_t* kbuf,
                        size_t kbuf_len,
                        size_t* klen);

/**
 * get_opaque_key() - Get an opaque key given an access handle
 *
 * @access_token: pointer to an access_token_t
 */
uint32_t get_opaque_key(const uuid_t* uuid,
                        const char* access_token,
                        uint8_t* kbuf,
                        size_t kbuf_len,
                        size_t* klen);

uint32_t hwaes_get_opaque_key(const char* access_token,
                        uint8_t* kbuf,
                        size_t kbuf_len,
                        size_t* klen);

void hwkey_init_srv_provider(void);

void hwkey_install_keys(const struct hwkey_keyslot* keys, unsigned int kcnt);

int hwkey_start_service(void);

uint32_t derive_key_v1(const uuid_t* uuid,
                       const uint8_t* ikm_data,
                       size_t ikm_len,
                       uint8_t* key_data,
                       size_t* key_len);

uint32_t mp_dec(uint8_t* enc, size_t size, uint8_t* out);

__END_CDECLS
