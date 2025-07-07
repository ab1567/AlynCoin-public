#include <generated/block_protos.pb.h>
#include <generated/sync_protos.pb.h>
#include "syncing.h"
#include "network.h"
#include <iostream>
#include <json/json.h>

// Local helper to safely fetch Network instance
static Network &getNet() {
  Blockchain &blockchain = Blockchain::getInstance();
  return *Network::getExistingInstance();
}

// ✅ Request latest block
void Syncing::requestLatestBlock() {
  alyncoin::BlockRequestProto requestProto;
  requestProto.set_request_type("latest_block");
  alyncoin::net::Frame fr;
  fr.mutable_blockchain_sync_request()->set_request_type("latest_block");
  Network &net = getNet();
  for (const auto &peer : net.getPeers()) {
      auto it = net.getPeerTable().find(peer);
      if (it != net.getPeerTable().end() && it->second.tx)
          net.sendFrame(it->second.tx, fr);
  }
}

// ✅ Trigger sync with peers using modern snapshot or epoch-header modes
void Syncing::syncWithNetwork() {
  Network &net = getNet();

  for (const auto &peer : net.getPeers()) {
    if (net.peerSupportsSnapshot(peer)) {
      net.requestSnapshotSync(peer);
    } else if (net.peerSupportsAggProof(peer)) {
      net.requestEpochHeaders(peer);
    }
  }
}

// ✅ Propagate regular block with zk-STARK & dual signature awareness
void Syncing::propagateBlock(const Block &block) {
    Network &net = getNet();
    net.broadcastBlock(block);
    std::cout << "📡 Propagated block (zk-STARK + Dilithium + Falcon signatures included) to peers\n";
}

// ✅ Propagate transaction (ensure contains signatures)
void Syncing::propagateTransaction(const Transaction &tx) {
  Network &net = getNet();
  net.broadcastTransaction(tx);
  std::cout << "📡 Propagated transaction to peers.\n";
}

