#include "peer_manager.h"
#include "network.h"
#include "blockchain.h"
#include "json/json.h"
#include <iostream>
#include <algorithm>
#include <numeric>
#include <sstream>

PeerManager::PeerManager(PeerBlacklist* bl, Network* net)
    : blacklist(bl), network(net) {}

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

std::string PeerManager::getMajorityTipHash() {
    std::map<std::string, int> hashVotes;

    for (const std::string& peer : connected_peers) {
        if (peerTipHashes.count(peer)) {
            std::string hash = peerTipHashes[peer];
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
    std::string request = R"({"type": "block_request", "height": )" + std::to_string(height) + "}";

    for (const std::string& peer : connected_peers) {
        network->sendData(peer, request);
        std::string response = network->receiveData(peer);

        if (response.empty()) continue;

        alyncoin::BlockProto proto;
        if (!proto.ParseFromString(response)) continue;

        // ✅ Use unified constructor
        outBlock = Block::fromProto(proto);
        return true;
    }

    return false;
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
