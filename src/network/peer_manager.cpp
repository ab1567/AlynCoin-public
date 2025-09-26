#include "peer_manager.h"
#include "network.h"
#include "blockchain.h"
#include "json/json.h"
#include <iostream>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <chrono>

PeerManager::PeerManager(PeerBlacklist* bl, Network* net)
    : blacklist(bl), network(net), localWork(0) {}

static std::string ipPrefixPM(const std::string &ip) {
    if (ip.find(':') == std::string::npos) {
        std::stringstream ss(ip);
        std::string seg, out; int count = 0;
        while (std::getline(ss, seg, '.') && count < 3) {
            if (count) out += '.';
            out += seg; ++count;
        }
        return count == 3 ? out : std::string();
    }
    std::stringstream ss(ip);
    std::string seg, out; int count = 0;
    while (std::getline(ss, seg, ':') && count < 3) {
        if (count) out += ':';
        out += seg; ++count;
    }
    return count == 3 ? out : std::string();
}

bool PeerManager::registerPeer(const std::string &peer_id) {
    if (blacklist->isBlacklisted(peer_id)) {
        std::cout << "❌ Rejected blacklisted peer: " << peer_id << std::endl;
        return false;
    }
    std::string ip = peer_id.substr(0, peer_id.find(':'));
    std::string prefix = ipPrefixPM(ip);
    if (!prefix.empty()) {
        int cnt = 0;
        for (const auto &p : connected_peers) {
            std::string pIp = p.substr(0, p.find(':'));
            if (ipPrefixPM(pIp) == prefix)
                ++cnt;
        }
        if (cnt >= 2) {
            std::cerr << "⚠️ [registerPeer] netgroup limit" << std::endl;
            return false;
        }
    }
    return connectToPeer(peer_id);
}

bool PeerManager::connectToPeer(const std::string& peer_id) {
    if (blacklist->isBlacklisted(peer_id)) {
        std::cout << "❌ Rejected blacklisted peer: " << peer_id << std::endl;
        return false;
    }

    // Avoid duplicate insertions
    if (std::find(connected_peers.begin(), connected_peers.end(), peer_id) == connected_peers.end()) {
        connected_peers.push_back(peer_id);
    }

    std::cout << "✅ Connected to peer: " << peer_id << std::endl;

    // ✅ Reconnection only if peer not present in peerSockets
    if (network) {
        std::vector<std::string> activePeers = network->getPeers();
        if (std::find(activePeers.begin(), activePeers.end(), peer_id) == activePeers.end()) {
            std::cout << "🔁 [PeerManager] Peer not in active sockets: " << peer_id << ". Reconnecting...\n";

            size_t pos = peer_id.find(":");
            if (pos != std::string::npos) {
                std::string ip = peer_id.substr(0, pos);
                int port = std::stoi(peer_id.substr(pos + 1));
                network->connectToNode(ip, port);
            }
        }
    }

    return true;
}

void PeerManager::disconnectPeer(const std::string& peer_id) {
    connected_peers.erase(
        std::remove(connected_peers.begin(), connected_peers.end(), peer_id),
        connected_peers.end()
    );
    std::cout << "🔌 Disconnected peer: " << peer_id << std::endl;
}

std::vector<std::string> PeerManager::getConnectedPeers() {
    return connected_peers;
}

int PeerManager::getPeerCount() const {
    return connected_peers.size();
}

void PeerManager::setLocalWork(uint64_t work) {
    localWork = work;
}

uint64_t PeerManager::getLocalWork() const {
    return localWork;
}

void PeerManager::setPeerWork(const std::string& peer, uint64_t work) {
    peerWorks[peer] = work;
}

uint64_t PeerManager::getPeerWork(const std::string& peer) const {
    auto it = peerWorks.find(peer);
    if (it != peerWorks.end()) return it->second;
    return 0;
}

uint64_t PeerManager::getMaxPeerWork() const {
    uint64_t maxW = 0;
    for (const auto& kv : peerWorks) {
        if (kv.second > maxW)
            maxW = kv.second;
    }
    return maxW;
}

void PeerManager::setExternalAddress(const std::string &address) {
    externalAddress_ = address;
}

std::string PeerManager::getExternalAddress() const { return externalAddress_; }

uint64_t PeerManager::getMedianNetworkHeight() {
    std::vector<int> heights;

    for (const std::string& peer : connected_peers) {
        if (peerHeights.count(peer)) {
            int h = peerHeights[peer];
            if (h >= 0)
                heights.push_back(h);
        }
    }

    if (heights.empty()) return 0;

    std::sort(heights.begin(), heights.end());
    return heights[heights.size() / 2];
}

std::string PeerManager::getMajorityTipHash() const {
    std::map<std::string, int> hashVotes;

    for (const std::string& peer : connected_peers) {
        auto it = peerTipHashes.find(peer);
        if (it != peerTipHashes.end()) {
            const std::string& hash = it->second;
            if (hash.empty() || hash.length() < 64) continue;
            hashVotes[hash]++;
        }
    }

    if (hashVotes.empty()) {
        std::cerr << "⚠️ [PeerManager] No valid tip hashes received from peers.\n";
        return "";
    }

    auto majority = std::max_element(
        hashVotes.begin(), hashVotes.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });

    return majority->first;
}

bool PeerManager::fetchBlockAtHeight(int height, Block& outBlock) {
    alyncoin::net::Frame request;
    request.mutable_block_request()->set_index(height);

    auto pending = std::make_shared<PendingBlockRequest>();
    {
        std::lock_guard<std::mutex> lock(pendingRequestMutex);
        pendingBlockRequests[height] = pending;
    }

    auto cleanup = [this, height, pending]() {
        std::lock_guard<std::mutex> lock(pendingRequestMutex);
        auto it = pendingBlockRequests.find(height);
        if (it != pendingBlockRequests.end() && it->second == pending)
            pendingBlockRequests.erase(it);
    };

    for (const std::string& peer : connected_peers) {
        const auto& table = network->getPeerTable();
        auto it = table.find(peer);
        if (it == table.end() || !it->second.tx) continue;

        network->sendFrame(it->second.tx, request, /*immediate=*/true);

        std::unique_lock<std::mutex> lk(pending->mutex);
        bool gotBlock = pending->cv.wait_for(
            lk, std::chrono::seconds(5), [&pending]() { return pending->fulfilled; });
        if (gotBlock) {
            outBlock = pending->block;
            cleanup();
            return true;
        }
        // Timed out waiting for this peer. Try next.
    }

    cleanup();
    return false;
}

void PeerManager::handleBlockResponse(const Block& block) {
    std::shared_ptr<PendingBlockRequest> pending;
    int height = static_cast<int>(block.getIndex());
    {
        std::lock_guard<std::mutex> lock(pendingRequestMutex);
        auto it = pendingBlockRequests.find(height);
        if (it != pendingBlockRequests.end())
            pending = it->second;
    }

    if (!pending)
        return;

    {
        std::lock_guard<std::mutex> lk(pending->mutex);
        pending->block = block;
        pending->fulfilled = true;
    }
    pending->cv.notify_all();
}
void PeerManager::setPeerHeight(const std::string& peer, int height) {
    if (height < 0) return;
    peerHeights[peer] = height;
}
int PeerManager::getPeerHeight(const std::string& peer) const {
    auto it = peerHeights.find(peer);
    if (it != peerHeights.end()) return it->second;
    return -1;
}

std::string PeerManager::getPeerTipHash(const std::string& peer) const {
    auto it = peerTipHashes.find(peer);
    if (it != peerTipHashes.end()) return it->second;
    return "";
}

void PeerManager::setPeerTipHash(const std::string& peer, const std::string& tipHash) {
    peerTipHashes[peer] = tipHash;
}
void PeerManager::recordTipHash(const std::string& peer, const std::string& tipHash) {
    setPeerTipHash(peer, tipHash);
}

int PeerManager::getMaxPeerHeight() const {
    int maxH = -1;
    for (const auto& kv : peerHeights) {
        if (kv.second > maxH)
            maxH = kv.second;
    }
    return maxH;
}

std::string PeerManager::getConsensusTipHash(int localHeight) const {
    std::map<std::string, int> hashVotes;
    int threshold = static_cast<int>(localHeight * 0.10);
    for (const std::string& peer : connected_peers) {
        auto itH = peerHeights.find(peer);
        if (itH != peerHeights.end() && itH->second < threshold)
            continue;
        auto it = peerTipHashes.find(peer);
        if (it != peerTipHashes.end()) {
            const std::string& hash = it->second;
            if (hash.empty() || hash.length() < 64) continue;
            hashVotes[hash]++;
        }
    }
    if (hashVotes.empty())
        return getMajorityTipHash();
    auto majority = std::max_element(
        hashVotes.begin(), hashVotes.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    return majority->first;
}
