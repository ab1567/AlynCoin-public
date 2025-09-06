#ifndef ALYNCOIN_CONSTANTS_H
#define ALYNCOIN_CONSTANTS_H
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

inline constexpr std::string_view GENESIS_BLOCK_HASH =
    "048d862090b48c81ef6d33580df428d979c3f01b7b282d1c55d9e481b9e1bb69";

inline constexpr int DESYNC_THRESHOLD = 5000;

// allow larger snapshot transfers for cold sync
// Network stacks are happier with smaller writes, so cap snapshot chunks
// at 256 KiB to avoid overrunning peer receive windows.
// Keeping below MAX_WIRE_PAYLOAD to account for frame overhead
inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 250 * 1024; // 250 KiB
inline constexpr std::size_t MAX_PEERS = 32;                       // hard cap
inline constexpr int MAX_TAIL_BLOCKS = 256;      // limit tail block batches
// Peers will exchange up to 100 blocks directly before snapshotting.
inline constexpr int TAIL_SYNC_THRESHOLD = 100;   // height gap for tail sync
// Increased to support larger batch frames
inline constexpr std::size_t MAX_WIRE_PAYLOAD = 1024 * 1024; // 1 MiB frame cap
inline constexpr std::size_t MAX_TAIL_PAYLOAD = 200 * 1024; // safe tail chunk
inline constexpr std::size_t MAX_INV_PER_MSG = 500;         // inventory batch cap
// Limit blocks included in a snapshot to avoid sending the full chain
inline constexpr int MAX_SNAPSHOT_BLOCKS = 1000;
#endif // ALYNCOIN_CONSTANTS_H
