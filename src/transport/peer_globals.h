#pragma once
#include "block.h"
#include "transport/transport.h"
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>
#include <chrono>

// Per-peer state used during sync and message reassembly
struct PeerState {
  std::string jsonBuf;
  std::string prefixBuf; // holds partial protocol prefix across chunks
  std::vector<Block> orphanBuf;
  std::string snapshotB64;
  enum class SnapState {
    Idle,
    WaitMeta,
    WaitChunks
  } snapState{SnapState::Idle};
  std::string snapshotRoot;
  size_t snapshotExpectBytes{0};
  size_t snapshotReceived{0};
  bool snapshotActive{false};
  bool snapshotServing{false};
  size_t snapshotChunkPreference{0};
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
  bool headerBridgeActive{false};
  std::unordered_set<std::string> headerAnchorsRequested;
  int headerBestCommonHeight{-1};
  std::string headerBestCommonHash;
  int headerLastBinaryProbe{-1};
  std::mutex m;
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
