#include "network.h"

void Network::requestEpochHeaders(const std::string& /*peerId*/) {
void Network::requestEpochHeaders(const std::string& peerId) {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    auto it = peerTransports.find(peerId);
    if (it == peerTransports.end() || !it->second.tx) return;

    alyncoin::BlockchainSyncProto proto;
    proto.set_request_type("epoch_headers");

    alyncoin::net::Frame fr;
    *fr.mutable_blockchain_sync_request() = proto;
    sendFrame(it->second.tx, fr);
}
