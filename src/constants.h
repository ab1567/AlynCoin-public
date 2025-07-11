#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

/* 64 lower-case hex zeros – canonical “null” parent-hash */
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

// Use a minimal difficulty for the genesis block. A large value causes
// massive allocations when computing the initial accumulated work.
inline constexpr uint32_t GENESIS_DIFFICULTY = 1;

inline constexpr int DESYNC_THRESHOLD = 5000;

// allow larger snapshot transfers for cold sync
// Network stacks are happier with smaller writes, so cap snapshot chunks
// at 500 KiB by default to avoid overrunning peer receive windows.
// Keeping below MAX_WIRE_PAYLOAD to account for frame overhead
inline constexpr std::size_t DEFAULT_MAX_SNAPSHOT_CHUNK_SIZE = 500 * 1024; // 500 KiB
inline constexpr std::size_t DEFAULT_MAX_PEERS = 32;                       // hard cap
inline constexpr int MAX_TAIL_BLOCKS = 256;      // limit tail block batches
// Increased wire payload limit to handle larger blocks and snapshots
inline constexpr std::size_t MAX_WIRE_PAYLOAD = 512 * 1024; // 512 KiB frame cap
inline constexpr std::size_t MAX_TAIL_PAYLOAD = 200 * 1024; // safe tail chunk
inline constexpr std::size_t MAX_INV_PER_MSG = 500;         // inventory batch cap
