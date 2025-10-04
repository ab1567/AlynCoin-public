#include "headers_sync.h"
#include "block.h"
#include "blockchain.h"
#include "network.h"

static Network &getNet() {
    return *Network::getExistingInstance();
}

void HeadersSync::requestHeaders(const std::string &peer, const std::string &fromHash) {
    Network &net = getNet();
    auto snapshot = net.getPeerSnapshot(peer);
    if (!snapshot.transport || !snapshot.transport->isOpen())
        return;
    alyncoin::net::Frame fr;
    fr.mutable_get_headers()->set_from_hash(fromHash);
    net.sendFrame(snapshot.transport, fr);
}

void HeadersSync::handleHeaders(const std::string &peer, const alyncoin::net::Headers &proto) {
    std::vector<HeaderRecord> headers;
    headers.reserve(proto.headers_size());
    for (const auto &pb : proto.headers()) {
        try {
            Block tmp = Block::fromProto(pb, true);
            HeaderRecord rec;
            rec.hash = tmp.getHash();
            rec.previousHash = tmp.getPreviousHash();
            rec.index = tmp.getIndex();
            rec.accumulatedWork = tmp.getAccumulatedWork();
            headers.emplace_back(std::move(rec));
        } catch (const std::exception &ex) {
            std::cerr << "⚠️ [HeadersSync] Failed to parse header from peer "
                      << peer << ": " << ex.what() << "\n";
        } catch (...) {
            std::cerr << "⚠️ [HeadersSync] Failed to parse header from peer "
                      << peer << "\n";
        }
    }
    if (auto net = Network::getExistingInstance())
        net->handleHeaderResponse(peer, headers);
}
