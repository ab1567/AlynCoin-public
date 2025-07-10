#pragma once
#include "block.h"
#include "transport/transport.h"
#include "peer_state.h"
#include <memory>
#include <shared_mutex>
#include <boost/asio/strand.hpp>
#include <boost/asio/io_context.hpp>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include <chrono>

struct PeerEntry {
  std::shared_ptr<Transport> tx;
  std::shared_ptr<PeerState> state;
  bool initiatedByUs{false};
  std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>> strand;
};

// Canonical global peer table and mutex for the entire app:
extern std::unordered_map<std::string, PeerEntry> peerTransports;
extern std::shared_mutex peersMutex;
