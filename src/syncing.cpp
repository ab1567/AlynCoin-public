#include "syncing.h"
#include "network.h"
#include "generated/sync_protos.pb.h"
#include "generated/block_protos.pb.h"

void Syncing::requestLatestBlock() {
    alyncoin::BlockRequestProto requestProto;  // ✅ FIXED
    requestProto.set_request_type("latest_block");

    std::string serializedData;
    requestProto.SerializeToString(&serializedData);

    Network::getInstance().broadcastMessage(serializedData);
}

void Syncing::syncWithNetwork() {
    alyncoin::BlockchainSyncProto syncProto;  // ✅ FIXED
    syncProto.set_request_type("full_sync");

    std::string serializedData;
    syncProto.SerializeToString(&serializedData);

    Network::getInstance().broadcastMessage(serializedData);
}


void Syncing::propagateBlock(const Block& block) {
    alyncoin::BlockProto blockProto = block.toProtobuf();
    
    std::string serializedBlock;
    blockProto.SerializeToString(&serializedBlock);
    
    Json::Value message;
    message["type"] = "block";
    message["data"] = serializedBlock;

    Json::StreamWriterBuilder writer;
    std::string messageStr = Json::writeString(writer, message);

    Network& net = Network::getInstance();
    for (const std::string& peer : net.getPeers()) {
        net.sendData(peer, messageStr);
    }
}

void Syncing::propagateTransaction(const Transaction& tx) {
    alyncoin::TransactionProto txProto;
    tx.serializeToProtobuf(txProto);

    std::string serializedTx;
    txProto.SerializeToString(&serializedTx);

    Network::getInstance().broadcastMessage(serializedTx);
}
