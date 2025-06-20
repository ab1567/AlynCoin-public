#pragma once
#include <string_view>
#include <cstddef>
#include <cstdint>

/* 64 lower-case hex zeros – canonical “null” parent-hash */
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

inline constexpr uint32_t GENESIS_DIFFICULTY = 0x1e777777;

inline constexpr int DESYNC_THRESHOLD = 5000;

// allow larger snapshot transfers for cold sync
inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 1024 * 1024; // 1 MiB
inline constexpr std::size_t MAX_PEERS               = 32;        // hard cap
