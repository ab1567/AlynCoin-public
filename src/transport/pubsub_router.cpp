#include "pubsub_router.h"
#include <algorithm>
#include <random>

void PubSubRouter::subscribe(const std::string& topic, Handler handler) {
    std::lock_guard<std::mutex> lock(mutex);
    subs[topic].push_back(std::move(handler));
}

void PubSubRouter::publish(const std::string& fromPeer, const std::string& topic, const std::string& payload) {
    const std::string msgId = topic + "|" + std::to_string(std::hash<std::string>{}(payload));
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!seenMessages.insert(msgId).second)
            return;
    }
    // Call local handlers
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = subs.find(topic);
        if (it != subs.end()) {
            for (auto& h : it->second) h(fromPeer, payload);
        }
    }
    // Gossip to peers
    gossip(fromPeer, topic, payload);
}

void PubSubRouter::addPeer(const std::string& peerId, std::function<void(const std::string&)> sendFunc) {
    std::lock_guard<std::mutex> lock(mutex);
    peers[peerId] = std::move(sendFunc);
}

void PubSubRouter::removePeer(const std::string& peerId) {
    std::lock_guard<std::mutex> lock(mutex);
    peers.erase(peerId);
}

void PubSubRouter::setFanout(int n) {
    fanout = n;
}

void PubSubRouter::gossip(const std::string& fromPeer, const std::string& topic, const std::string& payload) {
    std::vector<std::string> peerIds;
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& kv : peers)
            if (kv.first != fromPeer)
                peerIds.push_back(kv.first);
    }
    // Shuffle peers for random fan-out
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(peerIds.begin(), peerIds.end(), g);

    int sent = 0;
    for (const auto& peer : peerIds) {
        std::lock_guard<std::mutex> lock(mutex);
        if (peers.count(peer))
            peers[peer](R"({"topic":")" + topic + R"(","payload":")" + payload + R"("})");
        if (++sent >= fanout) break;
    }
}
