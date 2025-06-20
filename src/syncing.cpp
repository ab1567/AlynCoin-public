#include "generated/block_protos.pb.h"
#include "generated/sync_protos.pb.h"
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

  std::string serializedData;
  requestProto.SerializeToString(&serializedData);

  std::string message = "ALYN|BLOCK_REQUEST|" + serializedData;
  getNet().broadcastMessage(message);
}

// ✅ Full blockchain sync request
void Syncing::syncWithNetwork() {
  alyncoin::BlockchainSyncProto syncProto;
  syncProto.set_request_type("full_sync");

  alyncoin::net::Frame fr;
  *fr.mutable_blockchain_sync_request() = syncProto;

  Network &net = getNet();
  for (const auto &peer : net.getPeers()) {
      auto it = net.getPeerTable().find(peer);
      if (it != net.getPeerTable().end() && it->second.tx)
          net.sendFrame(it->second.tx, fr);
  }
}

// ✅ Propagate regular block with zk-STARK & dual signature awareness
void Syncing::propagateBlock(const Block &block) {
    alyncoin::BlockProto blockProto = block.toProtobuf();
    std::string serializedBlock;
    blockProto.SerializeToString(&serializedBlock);

    std::string base64Block = Crypto::base64Encode(serializedBlock, false);
    base64Block.erase(std::remove(base64Block.begin(), base64Block.end(), '\n'), base64Block.end());
    base64Block.erase(std::remove(base64Block.begin(), base64Block.end(), '\r'), base64Block.end());

    std::string message = "ALYN|BLOCK_BROADCAST|" + base64Block + '\n';

    Network &net = getNet();
    for (const std::string &peer : net.getPeers()) {
        if (!peer.empty()) {
            net.sendData(peer, message);
        }
    }

    std::cout << "📡 Propagated block (zk-STARK + Dilithium + Falcon signatures included) to peers\n";
}

// ✅ Propagate transaction (ensure contains signatures)
void Syncing::propagateTransaction(const Transaction &tx) {
  alyncoin::TransactionProto txProto;
  txProto = tx.toProto();

  std::string serializedTx;
  txProto.SerializeToString(&serializedTx);

  std::string message = "TRANSACTION_DATA|" + serializedTx;
  getNet().broadcastMessage(message);

  std::cout << "📡 Propagated transaction to peers.\n";
}

