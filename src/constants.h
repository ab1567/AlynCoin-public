#ifndef ALYNCOIN_CONSTANTS_H
#define ALYNCOIN_CONSTANTS_H
#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

/* 64 lower-case hex zeros – canonical “null” parent-hash */
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

// Placeholder Merkle root used when a block has no transactions
inline constexpr std::string_view EMPTY_TX_ROOT_HASH =
    "0c11a17c8610d35fe17aed2a5a5c682a6cdfb8b6ecf56a95605ebb1475b345de";

// Use a minimal difficulty for the genesis block. A large value causes
// massive allocations when computing the initial accumulated work.
inline constexpr uint32_t GENESIS_DIFFICULTY = 1;

// Base block reward and burn-rate bounds
inline constexpr double BASE_BLOCK_REWARD = 25.0; // Fixed block reward
inline constexpr double MAX_BURN_RATE = 0.05;     // Max 5% burn rate
inline constexpr double MIN_BURN_RATE = 0.01;     // Min 1% burn rate

inline constexpr int DESYNC_THRESHOLD = 5000;

// allow larger snapshot transfers for cold sync
// Network stacks are happier with smaller writes, so cap snapshot chunks
// at 32 KiB to avoid overrunning peer receive windows.
// Keeping below MAX_WIRE_PAYLOAD to account for frame overhead
inline constexpr std::size_t MAX_SNAPSHOT_CHUNK_SIZE = 32 * 1024; // 32 KiB
// Older peers silently drop frames that exceed ~64 KiB. Use this cap when
// advertising or transmitting snapshot chunks to remain compatible while still
// benefiting newer peers that can stream larger frames.
inline constexpr std::size_t SNAPSHOT_COMPAT_CHUNK_CAP = 64 * 1024; // 64 KiB
// Leave a small buffer so chunk frames never brush against the hard payload cap
inline constexpr std::size_t SNAPSHOT_FRAME_SAFETY_MARGIN = 1024; // 1 KiB wiggle room
// Allow a little extra headroom for peers whose framing or encoding adds a
// small amount of overhead on top of the advertised chunk size. Without this
// tolerance the receiver may discard perfectly valid snapshot data that is only
// a few bytes larger than the nominal limit.
inline constexpr std::size_t SNAPSHOT_CHUNK_TOLERANCE = 16 * 1024; // 16 KiB
inline constexpr std::size_t SNAPSHOT_ACK_WINDOW = 256 * 1024;     // Ack every 256 KiB
inline constexpr std::size_t SNAPSHOT_ACK_CHUNK_WINDOW = 8;         // Ack every 8 chunks
inline constexpr std::size_t SNAPSHOT_SESSION_ID_BYTES = 16;        // 128-bit token
inline constexpr std::size_t SNAPSHOT_SEND_WINDOW = 4;              // max in-flight chunks
inline constexpr int SNAPSHOT_ACK_TIMEOUT_MS = 2000;                // ack wait timeout
inline constexpr int SNAPSHOT_MAX_RETRIES = 3;                      // resend attempts
inline constexpr std::size_t MAX_PEERS = 32;                       // hard cap
inline constexpr int MAX_TAIL_BLOCKS = 256; // limit tail block batches
inline constexpr int FAST_SYNC_RECENT_BLOCKS = 256; // preview burst for lagging peers
inline constexpr int FAST_SYNC_TRIGGER_GAP = 2048;  // require sizeable gap before preview
// Peers will exchange up to 100 blocks directly before snapshotting.
inline constexpr int SNAPSHOT_PROACTIVE_GAP = 16; // remote must be 16 blocks ahead to force snapshot
inline constexpr int TAIL_SYNC_THRESHOLD = 32;    // height gap for tail sync before snapshotting
inline constexpr uint64_t SNAPSHOT_WORK_DELTA = 1024; // cumulative work delta to favour snapshots
// Increased to support larger batch frames
inline constexpr std::size_t MAX_WIRE_PAYLOAD = 512 * 1024; // 512 KiB frame cap
// Control frames (acks, requests, pings, etc.) should stay comfortably under
// this limit so they never monopolize the wire or starve data transfers.
inline constexpr std::size_t MAX_CONTROL_FRAME_PAYLOAD = 64 * 1024; // 64 KiB
inline constexpr std::size_t MAX_TAIL_PAYLOAD = 200 * 1024;  // safe tail chunk
inline constexpr std::size_t MAX_INV_PER_MSG = 500; // inventory batch cap
// Limit blocks included in a snapshot to avoid sending the full chain
inline constexpr int MAX_SNAPSHOT_BLOCKS = 1000;
inline constexpr uint32_t NETWORK_PROTO_VERSION = 3;
#endif // ALYNCOIN_CONSTANTS_H
