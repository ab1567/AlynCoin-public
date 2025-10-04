#include "peer_manager.h"
#include "network.h"
#include "blockchain.h"
#include "config.h"
#include "json/json.h"
#include "transport/peer_globals.h"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <iostream>
#include <numeric>
#include <sstream>
#include <unordered_set>
#include <vector>

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

static std::string maskEndpointForDisplay(const std::string &host) {
    if (host.empty())
        return host;

    const bool hasColon = host.find(':') != std::string::npos;
    if (!hasColon) {
        bool dottedDecimal = true;
        for (unsigned char ch : host) {
            if (!(std::isdigit(ch) || ch == '.')) {
                dottedDecimal = false;
                break;
            }
        }
        if (dottedDecimal) {
            std::stringstream ss(host);
            std::string seg;
            std::vector<std::string> parts;
            while (std::getline(ss, seg, '.')) {
                if (seg.empty())
                    return host;
                parts.push_back(seg);
            }
            if (parts.size() == 4) {
                parts.back() = "*";
                std::ostringstream oss;
                for (size_t i = 0; i < parts.size(); ++i) {
                    if (i)
                        oss << '.';
                    oss << parts[i];
                }
                return oss.str();
            }
        } else {
            if (host.size() > 4)
                return host.substr(0, host.size() - 2) + "**";
        }
        return host;
    }

    std::stringstream ss(host);
    std::string seg;
    std::vector<std::string> parts;
    while (std::getline(ss, seg, ':')) {
        if (!seg.empty())
            parts.push_back(seg);
    }
    if (!parts.empty()) {
        size_t keep = std::min<size_t>(parts.size(), 3);
        std::ostringstream oss;
        for (size_t i = 0; i < keep; ++i) {
            if (i)
                oss << ':';
            oss << parts[i];
        }
        oss << ":*";
        return oss.str();
    }

    return host;
}

PeerManager::PeerInsertResult PeerManager::tryInsertPeer(const std::string& peer_id,
                                                        bool enforceNetgroup) {
    std::lock_guard<std::mutex> guard(peerMutex);

    if (std::find(connected_peers.begin(), connected_peers.end(), peer_id) != connected_peers.end()) {
        return PeerInsertResult::AlreadyPresent;
    }

    const std::string ip = peer_id.substr(0, peer_id.find(':'));
    const std::string prefix = ipPrefixPM(ip);

    if (enforceNetgroup && !prefix.empty()) {
        int cnt = 0;
        for (const auto &p : connected_peers) {
            std::string pIp = p.substr(0, p.find(':'));
            if (ipPrefixPM(pIp) == prefix) {
                ++cnt;
                if (cnt >= 2) {
                    return PeerInsertResult::NetgroupLimit;
                }
            }
        }
    }

    connected_peers.push_back(peer_id);
    return PeerInsertResult::Added;
}

void PeerManager::announcePeerConnected(const std::string& peer_id) {
    std::cout << "✅ Connected to peer: " << peer_id << std::endl;

    if (!network) {
        return;
    }

    std::vector<std::string> activePeers = network->getPeers();
    if (std::find(activePeers.begin(), activePeers.end(), peer_id) == activePeers.end()) {
        std::cout << "🔁 [PeerManager] Peer not in active sockets: " << peer_id
                  << ". Reconnecting...\n";

        size_t pos = peer_id.find(":");
        if (pos != std::string::npos) {
            std::string ip = peer_id.substr(0, pos);
            int port = std::stoi(peer_id.substr(pos + 1));
            network->connectToNode(ip, port);
        }
    }
}

bool PeerManager::registerPeer(const std::string &peer_id) {
    if (blacklist->isBlacklisted(peer_id)) {
        std::cout << "❌ Rejected blacklisted peer: " << peer_id << std::endl;
        return false;
    }
    auto result = tryInsertPeer(peer_id, /*enforceNetgroup=*/true);
    if (result == PeerInsertResult::NetgroupLimit) {
        std::cerr << "⚠️ [registerPeer] netgroup limit" << std::endl;
        return false;
    }

    if (result == PeerInsertResult::Added) {
        announcePeerConnected(peer_id);
    }

    return true;
}

bool PeerManager::connectToPeer(const std::string& peer_id) {
    if (blacklist->isBlacklisted(peer_id)) {
        std::cout << "❌ Rejected blacklisted peer: " << peer_id << std::endl;
        return false;
    }

    auto result = tryInsertPeer(peer_id, /*enforceNetgroup=*/false);
    if (result == PeerInsertResult::Added) {
        announcePeerConnected(peer_id);
    }

    return true;
}

void PeerManager::disconnectPeer(const std::string& peer_id) {
    std::lock_guard<std::mutex> guard(peerMutex);
    connected_peers.erase(
        std::remove(connected_peers.begin(), connected_peers.end(), peer_id),
        connected_peers.end()
    );
    std::cout << "🔌 Disconnected peer: " << peer_id << std::endl;
}

std::vector<std::string> PeerManager::getConnectedPeers() {
    std::vector<std::string> peers;
    const bool hideEndpoints = getAppConfig().hide_peer_endpoints;
    std::vector<std::string> snapshot;
    {
        std::lock_guard<std::mutex> guard(peerMutex);
        snapshot = connected_peers;
    }

    std::unordered_set<std::string> seenPeerIds;
    std::unordered_set<std::string> seenEndpoints;

    if (network) {
        std::lock_guard<std::timed_mutex> netGuard(peersMutex);
        const auto &table = network->getPeerTable();
        peers.reserve(table.size());
        for (const auto &kv : table) {
            const auto &peerId = kv.first;
            const auto &entry = kv.second;
            if (!entry.tx || !entry.tx->isOpen())
                continue;

            std::string host = !entry.observedIp.empty() ? entry.observedIp : entry.ip;
            int port = entry.observedPort > 0 ? entry.observedPort : entry.port;

            std::string endpointKey;
            if (!hideEndpoints && !host.empty()) {
                std::ostringstream ep;
                ep << host;
                if (port > 0)
                    ep << ':' << port;
                endpointKey = ep.str();
            } else {
                endpointKey = peerId;
            }

            if (!seenEndpoints.insert(endpointKey).second)
                continue;

            std::ostringstream label;
            label << peerId;
            if (!host.empty()) {
                std::string displayHost = host;
                if (hideEndpoints)
                    displayHost = maskEndpointForDisplay(host);

                if (!displayHost.empty()) {
                    label << " (" << displayHost;
                    if (port > 0)
                        label << ':' << port;
                    label << ')';
                }
            }
            label << (entry.initiatedByUs ? " [outbound]" : " [inbound]");

            peers.push_back(label.str());
            seenPeerIds.insert(peerId);
        }
    }

    for (const auto &peerId : snapshot) {
        if (!seenPeerIds.insert(peerId).second)
            continue;
        peers.push_back(peerId);
    }

    return peers;
}

std::vector<std::string> PeerManager::getConnectedPeerIds() const {
    std::vector<std::string> snapshot;
    {
        std::lock_guard<std::mutex> guard(peerMutex);
        snapshot = connected_peers;
    }

    std::unordered_set<std::string> seenPeerIds;
    std::vector<std::string> ids;

    if (network) {
        std::lock_guard<std::timed_mutex> netGuard(peersMutex);
        const auto &table = network->getPeerTable();

        ids.reserve(table.size());
        std::unordered_set<std::string> dedupEndpoints;
        dedupEndpoints.reserve(table.size());

        for (const auto &kv : table) {
            const auto &peerId = kv.first;
            const auto &entry = kv.second;
            if (!entry.tx || !entry.tx->isOpen())
                continue;

            std::string host = !entry.observedIp.empty() ? entry.observedIp : entry.ip;
            int port = entry.observedPort > 0 ? entry.observedPort : entry.port;

            std::string endpointKey;
            if (!host.empty()) {
                std::ostringstream ep;
                ep << host;
                if (port > 0)
                    ep << ':' << port;
                endpointKey = ep.str();
            } else {
                endpointKey = peerId;
            }

            if (!dedupEndpoints.insert(endpointKey).second)
                continue;

            if (seenPeerIds.insert(peerId).second)
                ids.push_back(peerId);
        }
    }

    for (const auto &peerId : snapshot) {
        if (seenPeerIds.insert(peerId).second)
            ids.push_back(peerId);
    }

    return ids;
}

int PeerManager::getPeerCount() const {
    return static_cast<int>(getConnectedPeerIds().size());
}

void PeerManager::setLocalWork(uint64_t work) {
    std::lock_guard<std::mutex> guard(peerMutex);
    localWork = work;
}

uint64_t PeerManager::getLocalWork() const {
    std::lock_guard<std::mutex> guard(peerMutex);
    return localWork;
}

void PeerManager::setPeerWork(const std::string& peer, uint64_t work) {
    std::lock_guard<std::mutex> guard(peerMutex);
    peerWorks[peer] = work;
}

uint64_t PeerManager::getPeerWork(const std::string& peer) const {
    std::lock_guard<std::mutex> guard(peerMutex);
    auto it = peerWorks.find(peer);
    if (it != peerWorks.end()) return it->second;
    return 0;
}

uint64_t PeerManager::getMaxPeerWork() const {
    uint64_t maxW = 0;
    std::lock_guard<std::mutex> guard(peerMutex);
    for (const auto& kv : peerWorks) {
        if (kv.second > maxW)
            maxW = kv.second;
    }
    return maxW;
}

uint64_t PeerManager::getMedianPeerWork() const {
    std::vector<uint64_t> works;
    {
        std::lock_guard<std::mutex> guard(peerMutex);
        works.reserve(peerWorks.size());
        for (const auto &kv : peerWorks) {
            if (kv.second > 0)
                works.push_back(kv.second);
        }
    }

    if (works.empty())
        return 0;

    std::sort(works.begin(), works.end());
    return works[works.size() / 2];
}

void PeerManager::setExternalAddress(const std::string &address) {
    std::lock_guard<std::mutex> guard(peerMutex);
    externalAddress_ = address;
}

std::string PeerManager::getExternalAddress() const {
    std::lock_guard<std::mutex> guard(peerMutex);
    return externalAddress_;
}

uint64_t PeerManager::getMedianNetworkHeight() {
    std::vector<int> heights;

    {
        std::lock_guard<std::mutex> guard(peerMutex);
        for (const std::string& peer : connected_peers) {
            auto it = peerHeights.find(peer);
            if (it != peerHeights.end()) {
                int h = it->second;
                if (h >= 0)
                    heights.push_back(h);
            }
        }
    }

    if (heights.empty()) return 0;

    std::sort(heights.begin(), heights.end());
    return heights[heights.size() / 2];
}

std::string PeerManager::getMajorityTipHash() const {
    std::map<std::string, int> hashVotes;

    std::vector<std::string> peerHashes;
    {
        std::lock_guard<std::mutex> guard(peerMutex);
        peerHashes.reserve(connected_peers.size());
        for (const std::string& peer : connected_peers) {
            auto it = peerTipHashes.find(peer);
            if (it != peerTipHashes.end()) {
                peerHashes.push_back(it->second);
            }
        }
    }

    for (const auto& hash : peerHashes) {
        if (hash.empty() || hash.length() < 64) continue;
        hashVotes[hash]++;
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

    auto peersSnapshot = getConnectedPeerIds();
    for (const std::string& peer : peersSnapshot) {
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
    std::lock_guard<std::mutex> guard(peerMutex);
    peerHeights[peer] = height;
}
int PeerManager::getPeerHeight(const std::string& peer) const {
    std::lock_guard<std::mutex> guard(peerMutex);
    auto it = peerHeights.find(peer);
    if (it != peerHeights.end()) return it->second;
    return -1;
}

std::string PeerManager::getPeerTipHash(const std::string& peer) const {
    std::lock_guard<std::mutex> guard(peerMutex);
    auto it = peerTipHashes.find(peer);
    if (it != peerTipHashes.end()) return it->second;
    return "";
}

void PeerManager::setPeerTipHash(const std::string& peer, const std::string& tipHash) {
    std::lock_guard<std::mutex> guard(peerMutex);
    peerTipHashes[peer] = tipHash;
}
void PeerManager::recordTipHash(const std::string& peer, const std::string& tipHash) {
    setPeerTipHash(peer, tipHash);
}

int PeerManager::getMaxPeerHeight() const {
    int maxH = -1;
    std::lock_guard<std::mutex> guard(peerMutex);
    for (const auto& kv : peerHeights) {
        if (kv.second > maxH)
            maxH = kv.second;
    }
    return maxH;
}

std::string PeerManager::getConsensusTipHash(int localHeight) const {
    std::map<std::string, int> hashVotes;
    int threshold = static_cast<int>(localHeight * 0.10);
    std::vector<std::string> peerHashes;
    {
        std::lock_guard<std::mutex> guard(peerMutex);
        peerHashes.reserve(connected_peers.size());
        for (const std::string& peer : connected_peers) {
            auto itH = peerHeights.find(peer);
            if (itH != peerHeights.end() && itH->second < threshold)
                continue;
            auto it = peerTipHashes.find(peer);
            if (it != peerTipHashes.end()) {
                peerHashes.push_back(it->second);
            }
        }
    }
    for (const auto& hash : peerHashes) {
        if (hash.empty() || hash.length() < 64) continue;
        hashVotes[hash]++;
    }
    if (hashVotes.empty())
        return getMajorityTipHash();
    auto majority = std::max_element(
        hashVotes.begin(), hashVotes.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    return majority->first;
}

void PeerManager::recordCommonAncestor(const std::string &peer,
                                       const std::string &hash, int height) {
    if (hash.empty() || height < 0)
        return;
    std::lock_guard<std::mutex> guard(peerMutex);
    peerCommonHashes[peer] = hash;
    peerCommonHeights[peer] = height;
}

std::string PeerManager::getConsensusCommonHash(int localHeight) const {
    std::lock_guard<std::mutex> guard(peerMutex);
    std::map<std::string, int> voteCount;
    std::map<std::string, int> maxHeight;
    for (const auto &kv : peerCommonHashes) {
        const std::string &peer = kv.first;
        const std::string &hash = kv.second;
        auto itHeight = peerCommonHeights.find(peer);
        if (itHeight == peerCommonHeights.end())
            continue;
        int height = itHeight->second;
        if (height < 0 || height > localHeight)
            continue;
        if (hash.empty())
            continue;
        voteCount[hash]++;
        auto &storedHeight = maxHeight[hash];
        if (height > storedHeight)
            storedHeight = height;
    }
    if (voteCount.empty())
        return std::string();

    auto best = std::max_element(
        voteCount.begin(), voteCount.end(),
        [&](const auto &a, const auto &b) {
            if (a.second != b.second)
                return a.second < b.second;
            return maxHeight[a.first] < maxHeight[b.first];
        });
    return best->first;
}
