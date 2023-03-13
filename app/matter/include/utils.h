/*
 * Copyright 2023 NXP
 */

namespace matter {
constexpr uint8_t kMinValidFabricIndex  = 1;
constexpr uint8_t kMaxValidFabricIndex  = UINT8_MAX - 1;
constexpr uint8_t kUndefinedFabricIndex = 0;

constexpr bool IsValidFabricIndex(uint8_t fabricIndex) {
    return (fabricIndex >= kMinValidFabricIndex) && (fabricIndex <= kMaxValidFabricIndex);
}

}
