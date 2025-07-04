#pragma once
#include "block.h"
#include "transport/transport.h"
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include <chrono>

// Per-peer state used during sync and message reassembly
struct PeerState {
  std::string fullChainB64;
  std::string legacyChainB64;
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
  bool fullChainActive{false};
  bool supportsAggProof{false};
  bool supportsSnapshot{false};
  bool supportsWhisper{false};
  bool supportsTls{false};
  bool supportsBanDecay{false};
  uint64_t frameCountMin{0};
  uint64_t byteCountMin{0};
  int limitStrikes{0};
  int misScore{0};
  std::chrono::steady_clock::time_point banUntil{};
  std::array<uint8_t, 32> linkKey{};
  std::mutex m;
};

struct PeerEntry {
  std::shared_ptr<Transport> tx;
  std::shared_ptr<PeerState> state;
  bool initiatedByUs{false};
};

// Canonical global peer table and mutex for the entire app:
extern std::unordered_map<std::string, PeerEntry> peerTransports;
extern std::timed_mutex peersMutex;
