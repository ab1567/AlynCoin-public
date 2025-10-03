#ifndef HEALTH_MONITOR_H
#define HEALTH_MONITOR_H

#include <string>
#include <vector>
#include <chrono>

class PeerManager;
class Blockchain;

struct NodeHealthStatus {
    bool isHealthy{false};
    std::string reason;
    uint64_t localHeight{0};
    uint64_t networkHeight{0};
    std::string localTipHash;
    std::string expectedTipHash;
    std::string consensusCommonHash;
    size_t connectedPeers{0};
    size_t networkConnectedPeers{0};
    bool farBehind{false};
};

class HealthMonitor {
public:
    HealthMonitor(Blockchain* blockchain, PeerManager* peerManager);

    NodeHealthStatus checkHealth();
    void logStatus(const NodeHealthStatus& status);
    bool shouldTriggerRecovery(const NodeHealthStatus& status);

private:
    Blockchain* blockchain_;
    PeerManager* peerManager_;
    std::chrono::time_point<std::chrono::steady_clock> lastCheckTime_;
    std::chrono::time_point<std::chrono::steady_clock> lastPeerDialAttempt_;

    std::string getLocalTipHash() const;
    std::string getNetworkTipHash() const;
    uint64_t getNetworkHeight() const;
};

#endif // HEALTH_MONITOR_H
