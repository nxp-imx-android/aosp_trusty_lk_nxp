/*
 * Copyright 2017 The Android Open Source Project
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

#ifndef SECURE_STORAGE_MANAGER_H_
#define SECURE_STORAGE_MANAGER_H_

#include <include/UniquePtr.h>
#include <lib/storage/storage.h>

extern "C" {
#include <include/matter_defs.h>
}
#include "matter.pb.h"
#include "matter_messages.h"

namespace matter {

class SecureStorageManager {
public:
    /**
     * Get a SecureStorageManager instance. The instance returned is shared with
     * all other callers, so it is not safe to call any api that does not commit
     * the transaction and then let other clients use the api. get_instance will
     * also discard any previous transaction to detect if the session is still
     * alive, and to make the starting state more predictable.
     */
    static SecureStorageManager* get_instance(bool translate_format = true);

    /**
     * These functions implement key and certificate chain storage on top
     * Trusty's secure storage service. All data is stored in the RPMB
     * filesystem.
     */

    /**
     * Writes |cert_size| bytes at |cert| to cert file associated with
     * |name|.
     */
    matter_error_t WriteCertToStorage(const char *name,
                                        const uint8_t* cert,
                                        uint32_t cert_size);

    /**
     * Reads cert associated with |cert_slot|.
     */
    Buffer ReadCertFromStorage(const char *name, matter_error_t* error);

    /**
     * Delete cert associated with |name|.
     */
    matter_error_t DeleteCert(const char *name, bool commit);

private:
    matter_error_t ReadMatterCert(const char *name, MatterCert** matter_cert_p);
    matter_error_t WriteMatterCert(const char *name, const MatterCert* matter_cert, bool commit);
    matter_error_t EncodeToFile(const pb_field_t fields[],
                                   const void* dest_struct,
                                   const char filename[],
                                   bool commit);
    matter_error_t DecodeFromFile(const pb_field_t fields[],
                                     void* dest_struct,
                                     const char filename[]);
    int StorageOpenSession(const char* type);
    void CloseSession();

    SecureStorageManager();
    ~SecureStorageManager();
    storage_session_t session_handle_;
};

}  // namespace matter

#endif  // SECURE_STORAGE_MANAGER_H_
