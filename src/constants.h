#pragma once
#include <string_view>
#include <cstddef>

/* 64 lower-case hex zeros – canonical “null” parent-hash */
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

inline constexpr int DESYNC_THRESHOLD = 5000;

inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 32 * 1024; // 32 KiB
inline constexpr std::size_t MAX_PEERS               = 32;        // hard cap
