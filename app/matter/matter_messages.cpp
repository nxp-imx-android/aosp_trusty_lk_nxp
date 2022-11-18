/*
 * Copyright 2014 The Android Open Source Project
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

#include <matter_messages.h>

namespace matter {

size_t MatterResponse::SerializedSize() const {
    if (error != MATTER_ERROR_OK)
        return sizeof(int32_t);
    else
        return sizeof(int32_t) + NonErrorSerializedSize();
}

uint8_t* MatterResponse::Serialize(uint8_t* buf, const uint8_t* end) const {
    buf = append_uint32_to_buf(buf, end, static_cast<uint32_t>(error));
    if (error == MATTER_ERROR_OK) buf = NonErrorSerialize(buf, end);
    return buf;
}

bool MatterResponse::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    if (!copy_uint32_from_buf(buf_ptr, end, &error)) return false;
    if (error != MATTER_ERROR_OK) return true;
    return NonErrorDeserialize(buf_ptr, end);
}

}  // namespace matter
