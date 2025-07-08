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
// at 256 KiB to avoid overrunning peer receive windows.
// Keeping below MAX_WIRE_PAYLOAD to account for frame overhead
// Allow larger snapshot transfers for cold sync without exceeding typical
// receive windows. 128 KiB works well across a wide range of networks and
// keeps memory usage modest during initial sync.
inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 128 * 1024; // 128 KiB
inline constexpr std::size_t MAX_PEERS = 32;                       // hard cap
inline constexpr int MAX_TAIL_BLOCKS = 256;      // limit tail block batches
inline constexpr std::size_t MAX_WIRE_PAYLOAD = 256 * 1024; // 256 KiB frame cap
inline constexpr std::size_t MAX_TAIL_PAYLOAD = 200 * 1024; // safe tail chunk
inline constexpr std::size_t MAX_INV_PER_MSG = 500;         // inventory batch cap
