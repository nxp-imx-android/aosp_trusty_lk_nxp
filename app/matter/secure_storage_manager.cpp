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

#include "secure_storage_manager.h"
#include "matter.pb.h"

#include <errno.h>
#include <stdio.h>
#include <uapi/err.h>

#include <lib/storage/storage.h>

#include <include/UniquePtr.h>
#include "pb_decode.h"
#include "pb_encode.h"

#define TLOG_TAG "matter_storage"

namespace matter {
// These values should match matter.proto descriptions.
static const int kCertSizeMax = 2048;

class FileCloser {
public:
    file_handle_t get_file_handle() { return file_handle; }
    int open_file(storage_session_t session,
                  const char* name,
                  uint32_t flags,
                  uint32_t opflags) {
        return storage_open_file(session, &file_handle, name, flags, opflags);
    }
    ~FileCloser() {
        if (file_handle) {
            storage_close_file(file_handle);
        }
    }

private:
    file_handle_t file_handle = 0;
};

SecureStorageManager* SecureStorageManager::get_instance(
        bool translate_format) {
    static SecureStorageManager instance;
    if (instance.session_handle_ != STORAGE_INVALID_SESSION) {
        int rc = storage_end_transaction(instance.session_handle_, false);
        if (rc < 0) {
            TLOGE("Error: existing session is stale.");
            storage_close_session(instance.session_handle_);
            instance.session_handle_ = STORAGE_INVALID_SESSION;
        }
    }
    if (instance.session_handle_ == STORAGE_INVALID_SESSION) {
        storage_open_session(&instance.session_handle_, STORAGE_CLIENT_TP_PORT);
        if (instance.session_handle_ == STORAGE_INVALID_SESSION) {
            return nullptr;
        }
    }
    return &instance;
}

matter_error_t SecureStorageManager::WriteCertToStorage(
        const char *name,
        const uint8_t* cert,
        uint32_t cert_size) {
    if (cert_size > kCertSizeMax) {
        return MATTER_ERROR_INVALID_INPUT_LENGTH;
    }
    MatterCert* matter_cert_p;
    matter_error_t err = ReadMatterCert(name, &matter_cert_p);
    if (err != MATTER_ERROR_OK) {
        CloseSession();
        return err;
    }
    // TODO how to handle if cert already exist?
    UniquePtr<MatterCert> matter_cert(matter_cert_p);
    matter_cert->has_cert = true;
    memcpy(matter_cert->cert.bytes, cert, cert_size);
    matter_cert->cert.size = cert_size;

    err = WriteMatterCert(name, matter_cert.get(), true);
    if (err != MATTER_ERROR_OK) {
        CloseSession();
    }
    return err;
}

Buffer SecureStorageManager::ReadCertFromStorage(
        const char *name,
        matter_error_t* error) {
    MatterCert* matter_cert_p;
    matter_error_t err = ReadMatterCert(name, &matter_cert_p);
    if (err != MATTER_ERROR_OK) {
        CloseSession();
        if (error) {
            *error = err;
        }
        return {};
    }
    UniquePtr<MatterCert> matter_cert(matter_cert_p);
    if (!matter_cert->has_cert) {
        if (error) {
            *error = MATTER_ERROR_INVALID_ARGUMENT;
        }
        return {};
    }
    Buffer result;
    if (!result.Reinitialize(matter_cert->cert.bytes, matter_cert->cert.size)) {
        if (error) {
            *error = MATTER_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        return {};
    }

    *error = MATTER_ERROR_OK;
    return result;
}

matter_error_t SecureStorageManager::DeleteCert(const char *name, bool commit) {
    int rc = storage_delete_file(session_handle_, name,
                                 commit ? STORAGE_OP_COMPLETE : 0);
    if (rc < 0 && rc != ERR_NOT_FOUND) {
        TLOGE("Error: [%d] deleting storage object '%s'", rc, name);
        if (commit) {
            // If DeleteKey is part of a larger operations, then do not close
            // the session.
            CloseSession();
        }
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    return MATTER_ERROR_OK;
}

matter_error_t SecureStorageManager::ReadMatterCert(
        const char *name,
        MatterCert** matter_cert_p) {
    UniquePtr<MatterCert> matter_cert(
            new (std::nothrow) MatterCert(MatterCert_init_zero));
    if (!matter_cert.get()) {
        return MATTER_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    matter_error_t err = DecodeFromFile(MatterCert_fields, matter_cert.get(), name);
    if (err < 0) {
        TLOGE("Error: [%d] decoding from file '%s'", err, name);
        return err;
    }
    *matter_cert_p = matter_cert.release();
    return MATTER_ERROR_OK;
}

matter_error_t SecureStorageManager::WriteMatterCert(
        const char *name,
        const MatterCert* matter_cert,
        bool commit) {

    return EncodeToFile(MatterCert_fields, matter_cert, name, commit);
}

void SecureStorageManager::CloseSession() {
    if (session_handle_ != STORAGE_INVALID_SESSION) {
        storage_close_session(session_handle_);
        session_handle_ = STORAGE_INVALID_SESSION;
    }
}

struct FileStatus {
    /* How many bytes handled in the file. */
    uint64_t bytes_handled;
    file_handle_t file_handle;
    FileStatus() : bytes_handled(0), file_handle(0) {}
};

bool write_to_file_callback(pb_ostream_t* stream,
                            const uint8_t* buf,
                            size_t count) {
    FileStatus* file_status = reinterpret_cast<FileStatus*>(stream->state);
    /* Do not commit the write. */
    int rc = storage_write(file_status->file_handle, file_status->bytes_handled,
                           buf, count, 0);
    if (rc < 0 || static_cast<size_t>(rc) < count) {
        TLOGE("Error: failed to write to file: %d\n", rc);
        return false;
    }
    file_status->bytes_handled += rc;
    return true;
}

bool read_from_file_callback(pb_istream_t* stream, uint8_t* buf, size_t count) {
    if (buf == NULL) {
        return false;
    }
    FileStatus* file_status = reinterpret_cast<FileStatus*>(stream->state);
    int rc = storage_read(file_status->file_handle, file_status->bytes_handled,
                          buf, count);
    if (rc < 0 || static_cast<size_t>(rc) < count) {
        TLOGE("Error: failed to read from file: %d\n", rc);
        return false;
    }
    file_status->bytes_handled += rc;
    return true;
}

matter_error_t SecureStorageManager::EncodeToFile(const pb_field_t fields[],
                                                     const void* dest_struct,
                                                     const char filename[],
                                                     bool commit) {
    FileCloser file;
    int rc = file.open_file(
            session_handle_, filename,
            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE, 0);
    if (rc < 0) {
        TLOGE("Error: failed to open file '%s': %d\n", filename, rc);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    FileStatus new_file_status;
    new_file_status.file_handle = file.get_file_handle();
    pb_ostream_t stream = {&write_to_file_callback, &new_file_status, SIZE_MAX,
                           0, 0};
    if (!pb_encode(&stream, fields, dest_struct)) {
        TLOGE("Error: encoding fields to file '%s'", filename);
        /* Abort the transaction. */
        storage_end_transaction(session_handle_, false);
        return MATTER_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    if (commit) {
        /* Commit the write. */
        rc = storage_end_transaction(session_handle_, true);
        if (rc < 0) {
            TLOGE("Error: failed to commit write transaction for file '%s': %d"
                  "\n",
                  filename, rc);
            return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        }
    }
    return MATTER_ERROR_OK;
}

matter_error_t SecureStorageManager::DecodeFromFile(
        const pb_field_t fields[],
        void* dest_struct,
        const char filename[]) {
    uint64_t file_size;
    FileCloser file;
    int rc = file.open_file(session_handle_, filename, 0, 0);
    if (rc == ERR_NOT_FOUND) {
        // File not exists
        return MATTER_ERROR_OK;
    }
    if (rc < 0) {
        TLOGE("Error: failed to open file '%s': %d\n", filename, rc);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    rc = storage_get_file_size(file.get_file_handle(), &file_size);
    if (rc < 0) {
        TLOGE("Error: failed to get size of attributes file '%s': %d\n", filename, rc);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    FileStatus new_file_status;
    new_file_status.file_handle = file.get_file_handle();
    pb_istream_t stream = {&read_from_file_callback, &new_file_status,
                           static_cast<size_t>(file_size), 0};
    if (!pb_decode(&stream, fields, dest_struct)) {
        TLOGE("Error: decoding fields from file '%s'", filename);
        return MATTER_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    return MATTER_ERROR_OK;
}

SecureStorageManager::SecureStorageManager() {
    session_handle_ = STORAGE_INVALID_SESSION;
}

SecureStorageManager::~SecureStorageManager() {
    CloseSession();
}

}  // namespace matter
