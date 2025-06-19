#pragma once
#include <cstdint>
#include <cstddef>

inline size_t encodeVarInt(uint64_t value, uint8_t* out) {
    size_t i = 0;
    while (value >= 0x80) {
        out[i++] = static_cast<uint8_t>(value) | 0x80;
        value >>= 7;
    }
    out[i++] = static_cast<uint8_t>(value);
    return i;
}

inline bool decodeVarInt(const uint8_t* data, size_t len, uint64_t* out, size_t* used) {
    uint64_t result = 0;
    int shift = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i++];
        result |= uint64_t(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            *out = result;
            *used = i;
            return true;
        }
        shift += 7;
        if (shift >= 64) return false;
    }
    return false;
}
