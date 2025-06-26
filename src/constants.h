#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

/* 64 lower-case hex zeros – canonical “null” parent-hash */
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

inline constexpr uint32_t GENESIS_DIFFICULTY = 0x1e777777;

inline constexpr int DESYNC_THRESHOLD = 5000;

// allow larger snapshot transfers for cold sync
// Network stacks are happier with smaller writes, so cap snapshot chunks
// at 256 KiB to avoid overrunning peer receive windows.
inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 256 * 1024; // 256 KiB
inline constexpr std::size_t MAX_PEERS = 32;                       // hard cap
