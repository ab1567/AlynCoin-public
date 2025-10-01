#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <limits>

// 64 lower-case hex zeros – canonical “null” parent-hash
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

// Placeholder Merkle root used when a block has no transactions
inline constexpr std::string_view EMPTY_TX_ROOT_HASH =
    "0c11a17c8610d35fe17aed2a5a5c682a6cdfb8b6ecf56a95605ebb1475b345de";

// Use a minimal difficulty for the genesis block to avoid huge allocations.
inline constexpr uint32_t GENESIS_DIFFICULTY = 1;

// Base block reward and burn-rate bounds
inline constexpr double BASE_BLOCK_REWARD = 25.0; // Fixed block reward
inline constexpr double MAX_BURN_RATE = 0.05;     // Max 5% burn rate
inline constexpr double MIN_BURN_RATE = 0.01;     // Min 1% burn rate

inline constexpr int DESYNC_THRESHOLD = 5000;

// Network payload/flow caps
inline constexpr std::size_t MAX_WIRE_PAYLOAD = 1024 * 1024; // 1 MiB frame cap
inline constexpr std::size_t MAX_TAIL_PAYLOAD = 200 * 1024;  // safe tail chunk
inline constexpr std::size_t MAX_INV_PER_MSG = 500;          // inventory batch cap

// Snapshot / sync policy
inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 250 * 1024; // 250 KiB
inline constexpr int MAX_SNAPSHOT_BLOCKS = 1000;
inline constexpr int MAX_TAIL_BLOCKS = 256;
inline constexpr int FAST_SYNC_RECENT_BLOCKS = 256;
inline constexpr int FAST_SYNC_TRIGGER_GAP = 2048;
inline constexpr int TAIL_SYNC_THRESHOLD = 100;

// Peer caps
inline constexpr std::size_t MAX_PEERS = std::numeric_limits<std::size_t>::max();
