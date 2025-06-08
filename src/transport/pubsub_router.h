#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <mutex>

class PubSubRouter {
public:
    using Handler = std::function<void(const std::string&, const std::string&)>;
    void subscribe(const std::string& topic, Handler handler);
    void publish(const std::string& fromPeer, const std::string& topic, const std::string& payload);

    // Integration:
    void addPeer(const std::string& peerId, std::function<void(const std::string&)> sendFunc);
    void removePeer(const std::string& peerId);

    // For testing/debug:
    void setFanout(int n);

private:
    void gossip(const std::string& fromPeer, const std::string& topic, const std::string& payload);

    std::unordered_map<std::string, std::vector<Handler>> subs;
    std::unordered_map<std::string, std::function<void(const std::string&)>> peers;
    std::unordered_set<std::string> seenMessages;
    std::mutex mutex;
    int fanout = 3; // sqrt(N) by default
};
