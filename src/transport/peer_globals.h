#pragma once
#include "block.h"
#include "transport/transport.h"
#include "peer_state.h"
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <deque>
#include <thread>
#include <condition_variable>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include <chrono>

struct PeerEntry {
  std::shared_ptr<Transport> tx;
  std::shared_ptr<PeerState> state;
  bool initiatedByUs{false};
  struct Outgoing {
    std::deque<std::string> queue;
    std::mutex m;
    std::condition_variable cv;
    std::thread writer;
    bool stop{false};
  };
  std::shared_ptr<Outgoing> out{std::make_shared<Outgoing>()};
};

// Canonical global peer table and mutex for the entire app:
extern std::unordered_map<std::string, PeerEntry> peerTransports;
extern std::shared_mutex peersMutex;
