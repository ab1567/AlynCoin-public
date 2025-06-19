#pragma once
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "block.h"
#include "transport/transport.h"

// Per-peer state used during sync and message reassembly
struct PeerState {
    std::string fullChainB64;
    std::string legacyChainB64;
    std::string jsonBuf;
    std::string prefixBuf;      // holds partial protocol prefix across chunks
    std::vector<Block> orphanBuf;
    std::string snapshotB64;
    bool        snapshotActive{false};
    bool        fullChainActive{false};
    bool        supportsAggProof{false};
    bool        supportsSnapshot{false};
    bool        supportsBinary{false};
    std::mutex  m;
};

struct PeerEntry {
    std::shared_ptr<Transport> tx;
    std::shared_ptr<PeerState> state;
};

// Canonical global peer table and mutex for the entire app:
extern std::unordered_map<std::string, PeerEntry> peerTransports;
extern std::timed_mutex peersMutex;

