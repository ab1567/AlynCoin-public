#pragma once
#include "block.h"
#include "transport/transport.h"
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <array>
#include <chrono>
#include <filesystem>
#include <map>
#include <algorithm>
#include <cstring>

#include "constants.h"

struct SnapshotSessionId {
  std::array<uint8_t, SNAPSHOT_SESSION_ID_BYTES> bytes{};
  bool hasValue{false};

  static SnapshotSessionId fromRaw(const std::string &raw) {
    SnapshotSessionId sid;
    if (raw.size() == SNAPSHOT_SESSION_ID_BYTES) {
      std::copy(reinterpret_cast<const uint8_t *>(raw.data()),
                reinterpret_cast<const uint8_t *>(raw.data()) +
                    SNAPSHOT_SESSION_ID_BYTES,
                sid.bytes.begin());
      sid.hasValue = true;
    } else if (!raw.empty()) {
      sid.clear();
    }
    return sid;
  }

  std::string toRaw() const {
    if (!hasValue)
      return {};
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       bytes.size());
  }

  void clear() {
    bytes.fill(0);
    hasValue = false;
  }

  bool empty() const { return !hasValue; }

  bool matchesRaw(const std::string &raw) const {
    if (raw.empty())
      return !hasValue;
    if (!hasValue || raw.size() != SNAPSHOT_SESSION_ID_BYTES)
      return false;
    return std::memcmp(bytes.data(), raw.data(), SNAPSHOT_SESSION_ID_BYTES) == 0;
  }
};

inline bool operator==(const SnapshotSessionId &lhs,
                       const SnapshotSessionId &rhs) {
  if (lhs.hasValue != rhs.hasValue)
    return false;
  if (!lhs.hasValue)
    return true;
  return lhs.bytes == rhs.bytes;
}

inline bool operator!=(const SnapshotSessionId &lhs,
                       const SnapshotSessionId &rhs) {
  return !(lhs == rhs);
}

inline bool operator==(const SnapshotSessionId &lhs, const std::string &rhs) {
  return lhs.matchesRaw(rhs);
}

inline bool operator==(const std::string &lhs, const SnapshotSessionId &rhs) {
  return rhs.matchesRaw(lhs);
}

inline bool operator!=(const SnapshotSessionId &lhs, const std::string &rhs) {
  return !(lhs == rhs);
}

inline bool operator!=(const std::string &lhs, const SnapshotSessionId &rhs) {
  return !(lhs == rhs);
}

struct SnapshotFileSink;

// Per-peer state used during sync and message reassembly
struct PeerState {
  std::string jsonBuf;
  std::string prefixBuf; // holds partial protocol prefix across chunks
  std::vector<Block> orphanBuf;
  enum class SyncMode {
    Idle,
    Headers,
    Blocks,
    Snapshot
  } syncMode{SyncMode::Idle};
  enum class SyncRole {
    Idle,
    ServingHeaders,
    ServingSnapshot,
    DownloadingHeaders,
    DownloadingSnapshot
  } wireMode{SyncRole::Idle};
  bool recovering{false};
  enum class SnapState {
    Idle,
    WaitMeta,
    WaitChunks,
    Verifying,
    Applying
  } snapState{SnapState::Idle};
  std::string snapshotRoot;
  size_t snapshotExpectBytes{0};
  size_t snapshotReceived{0};
  bool snapshotActive{false};
  bool snapshotServing{false};
  size_t snapshotChunkPreference{0};
  size_t snapshotChunkLimit{0};
  SnapshotSessionId snapshotSessionId;
  size_t snapshotLastAcked{0};
  std::shared_ptr<SnapshotFileSink> snapshotSink;
  std::filesystem::path snapshotTempPath;
  bool snapshotMetaReceived{false};
  bool snapshotRestartMetaSent{false};
  size_t snapshotChunksSinceAck{0};
  uint64_t snapshotChunksReceived{0};
  std::chrono::steady_clock::time_point snapshotLastProgressLog{};
  int staleSnapshotAckStrikes{0};
  SnapshotSessionId servingSnapshotSessionId;
  SnapshotSessionId previousServingSnapshotSessionId;
  std::string lastSnapshotMetaFrame;
  std::chrono::steady_clock::time_point lastSnapshotMetaSent{};
  std::chrono::steady_clock::time_point servingSnapshotSessionStarted{};
  std::chrono::steady_clock::time_point previousSnapshotSessionValidUntil{};
  struct OutgoingChunk {
    uint64_t offset{0};
    std::size_t length{0};
    std::chrono::steady_clock::time_point lastSent{};
    int retries{0};
  };
  std::deque<OutgoingChunk> snapshotOutstandingChunks;
  uint64_t snapshotAckedThrough{0};
  bool snapshotAbortFlag{false};
  std::condition_variable snapshotAckCv;
  bool snapshotImplicitStart{false};
  std::chrono::steady_clock::time_point snapshotImplicitSince{};
  struct PendingChunk {
    uint64_t offset{0};
    std::string data;
  };
  std::vector<PendingChunk> snapshotPendingChunks;
  size_t snapshotPendingBytes{0};
  std::map<uint64_t, std::string> snapshotDeferredChunks;
  size_t snapshotDeferredBytes{0};
  std::chrono::steady_clock::time_point snapshotLastOutOfOrderAck{};
  std::chrono::steady_clock::time_point nextSnapshotRequestAllowed{};
  std::chrono::steady_clock::time_point lastSnapshotThrottleLog{};
  int snapshotRequestStrikes{0};
  bool supportsAggProof{false};
  bool supportsSnapshot{false};
  bool supportsWhisper{false};
  bool supportsTls{false};
  bool supportsBanDecay{false};
  uint64_t frameCountMin{0};
  uint64_t byteCountMin{0};
  int limitStrikes{0};
  int misScore{0};
  int parseFailCount{0};
  uint32_t frameRev{0};
  std::string version;
  std::chrono::steady_clock::time_point banUntil{};
  int banCount{0};
  std::array<uint8_t, 32> linkKey{};
  int lastTailHeight{-1};
  std::string lastTailAnchor;
  uint32_t highestSeen{0};
  bool sentFastCatchup{false};
  std::chrono::steady_clock::time_point connectedAt{};
  std::chrono::steady_clock::time_point graceUntil{};
  uint64_t remoteNonce{0};
  std::chrono::steady_clock::time_point lastSnapshotServed{};
  std::chrono::steady_clock::time_point lastSnapshotRetry{};
  bool headerBridgeActive{false};
  std::unordered_set<std::string> headerAnchorsRequested;
  int headerBestCommonHeight{-1};
  std::string headerBestCommonHash;
  int headerLastBinaryProbe{-1};
  bool handshakeComplete{false};
  std::mutex m;
  std::deque<std::string> recentBlocksSent;
  std::unordered_set<std::string> recentBlocksSentSet;
  std::deque<std::string> recentBlocksReceived;
  std::unordered_set<std::string> recentBlocksReceivedSet;
  std::deque<std::size_t> recentHeadersFingerprints;
};

struct PeerEntry {
  std::shared_ptr<Transport> tx;
  std::shared_ptr<PeerState> state;
  bool initiatedByUs{false};
  int port{0};
  std::string ip; // original IP address
  int observedPort{0};
  std::string observedIp; // socket-observed remote address
};

// Canonical global peer table and mutex for the entire app:
extern std::unordered_map<std::string, PeerEntry> peerTransports;
extern std::timed_mutex peersMutex;
