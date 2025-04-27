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
quietPrint( "❌ Rejected blacklisted peer: " << peer_id << std::endl);
        return false;
    }

    connected_peers.push_back(peer_id);
quietPrint( "✅ Connected to peer: " << peer_id << std::endl);
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
        std::string msg = R"({"type": "height_request"})";
        network->sendData(peer, msg);

        std::string response = network->receiveData(peer);
        if (response.empty()) continue;

        Json::CharReaderBuilder reader;
        Json::Value jsonData;
        std::string errs;
        std::istringstream s(response);
        if (Json::parseFromStream(reader, s, &jsonData, &errs) && jsonData["type"] == "height_response") {
            int height = jsonData["data"].asInt();
            heights.push_back(height);
        }
    }

    if (heights.empty()) return 0;

    std::sort(heights.begin(), heights.end());
    return heights[heights.size() / 2];
}

std::string PeerManager::getMajorityTipHash() {
    std::map<std::string, int> hashVotes;

    for (const std::string& peer : connected_peers) {
        std::string msg = R"({"type": "tip_hash_request"})";
        network->sendData(peer, msg);

        std::string response = network->receiveData(peer);
        if (response.empty()) continue;

        Json::CharReaderBuilder reader;
        Json::Value jsonData;
        std::string errs;
        std::istringstream s(response);
        if (Json::parseFromStream(reader, s, &jsonData, &errs) && jsonData["type"] == "tip_hash_response") {
            std::string hash = jsonData["data"].asString();

            // ✅ Filter out empty hashes
            if (hash.empty() || hash.length() < 64) continue;

            hashVotes[hash]++;
        }
    }

    if (hashVotes.empty()) {
quietPrint( "⚠️ [PeerManager] No valid tip hashes received from peers.\n");
        return "";  // Avoid returning garbage
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
