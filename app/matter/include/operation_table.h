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

#include <UniquePtr.h>
#include <matter_defs.h>
#include <new>

namespace matter {

template <typename T>
class OperationTable {
  public:
    explicit OperationTable(size_t table_size) : table_size_(table_size) {}

    matter_error_t Add(UniquePtr<T>&& operation) {
        if (!table_) {
            table_.reset(new (std::nothrow) UniquePtr<T>[table_size_]);
            if (!table_) return MATTER_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        for (size_t i = 0; i < table_size_; ++i) {
            if (!table_[i]) {
                table_[i] = move(operation);
                return MATTER_ERROR_OK;
            }
        }
        return MATTER_ERROR_TOO_MANY_OPERATIONS;
    }

    T* Find(uint64_t handler) {
        if (handler == 0) return nullptr;

        if (!table_.get()) return nullptr;

        for (size_t i = 0; i < table_size_; ++i) {
            if (table_[i] && table_[i]->handler == handler) return table_[i].get();
        }
        return nullptr;
    }
    bool Delete(uint64_t handler) {
        if (!table_.get()) return false;

        for (size_t i = 0; i < table_size_; ++i) {
            if (table_[i] && table_[i]->handler == handler) {
                table_[i].reset();
                return true;
            }
        }
        return false;
    }

  private:
    UniquePtr<UniquePtr<T>[]> table_;
    size_t table_size_;
};

} //namespace matter
