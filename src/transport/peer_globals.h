#pragma once
#include "block.h"
#include "transport/transport.h"
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
  std::string snapshotSessionId;
  size_t snapshotLastAcked{0};
  std::shared_ptr<SnapshotFileSink> snapshotSink;
  std::filesystem::path snapshotTempPath;
  bool snapshotMetaReceived{false};
  bool snapshotRestartMetaSent{false};
  size_t snapshotChunksSinceAck{0};
  uint64_t snapshotChunksReceived{0};
  std::chrono::steady_clock::time_point snapshotLastProgressLog{};
  int staleSnapshotAckStrikes{0};
  std::string servingSnapshotSessionId;
  std::string lastSnapshotMetaFrame;
  std::chrono::steady_clock::time_point lastSnapshotMetaSent{};
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
  bool limitWindowTripped{false};
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
