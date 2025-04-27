#ifndef SELF_HEALING_NODE_H
#define SELF_HEALING_NODE_H

#include "self_healing/health_monitor.h"
#include "self_healing/sync_recovery.h"
#include <memory>
#include <chrono>

class Blockchain;
class PeerManager;
class HealthMonitor;
class SyncRecovery;

class SelfHealingNode {
public:
    SelfHealingNode(Blockchain* blockchain, PeerManager* peerManager);

    // Runs health check + recovery if needed
    void monitorAndHeal();

    // Can be scheduled in main node loop
    void runPeriodicCheck(std::chrono::seconds interval);

private:
    std::unique_ptr<HealthMonitor> healthMonitor_;
    std::unique_ptr<SyncRecovery> syncRecovery_;
    Blockchain* blockchain_;
    PeerManager* peerManager_;
};

#endif // SELF_HEALING_NODE_H
