#pragma once
#include <cstdint>
#include <cstddef>
#include <boost/asio/read.hpp>

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

template <typename Stream>
inline bool readVarIntBlocking(Stream& s, uint64_t& out) {
    uint64_t result = 0;
    int shift = 0;
    uint8_t b = 0;
    for (int i = 0; i < 10; ++i) {
        size_t got = boost::asio::read(s, boost::asio::buffer(&b, 1));
        if (got != 1)
            return false;
        result |= uint64_t(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            out = result;
            return true;
        }
        shift += 7;
    }
    return false;
}
