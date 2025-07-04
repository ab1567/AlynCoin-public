#include "headers_sync.h"
#include "network.h"
#include "blockchain.h"
#include "block.h"

static Network &getNet() {
    return *Network::getExistingInstance();
}

void HeadersSync::requestHeaders(const std::string &peer, const std::string &fromHash) {
    Network &net = getNet();
    auto it = net.getPeerTable().find(peer);
    if (it == net.getPeerTable().end() || !it->second.tx)
        return;
    alyncoin::net::Frame fr;
    fr.mutable_get_headers()->set_from_hash(fromHash);
    net.sendFrame(it->second.tx, fr);
}

void HeadersSync::handleHeaders(const std::string &peer, const alyncoin::net::Headers &proto) {
    Blockchain &bc = Blockchain::getInstance();
    for (const auto &pb : proto.headers()) {
        try {
            Block blk = Block::fromProto(pb, true);
            bc.addBlock(blk);
        } catch (...) {
            std::cerr << "⚠️ [HeadersSync] Failed to parse header from peer " << peer << "\n";
        }
    }
}
