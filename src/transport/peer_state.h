#pragma once
#include "block.h"
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <mutex>

enum class SyncState { Idle, WaitHandshake, WaitMeta, WaitChunks, SnapshotStream };

struct PeerState {
  std::string jsonBuf;
  std::string prefixBuf;
  std::vector<Block> orphanBuf;
  std::string snapshotB64;
  SyncState sync{SyncState::Idle};
  enum class SnapState {
    Idle,
    WaitMeta,
    WaitChunks
  } snapState{SnapState::Idle};
  std::string snapshotRoot;
  size_t snapshotExpectBytes{0};
  size_t snapshotReceived{0};
  bool snapshotActive{false};
  bool supportsAggProof{false};
  bool supportsSnapshot{false};
  bool supportsWhisper{false};
  bool supportsTls{false};
  bool supportsBanDecay{false};
  bool wantSnapshot{false};
  uint64_t frameCountMin{0};
  uint64_t byteCountMin{0};
  int limitStrikes{0};
  int misScore{0};
  uint32_t frameRev{0};
  std::string version;
  std::chrono::steady_clock::time_point banUntil{};
  int banCount{0};
  std::array<uint8_t, 32> linkKey{};
  int lastTailHeight{-1};
  std::string lastTailAnchor;
  uint32_t highestSeen{0};
  std::mutex m;
};

