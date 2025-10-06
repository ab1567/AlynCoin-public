#ifndef SELF_HEALING_NODE_H
#define SELF_HEALING_NODE_H

#include "self_healing/health_monitor.h"
#include "self_healing/sync_recovery.h"
#include <memory>
#include <chrono>
#include <cstddef>

class Blockchain;
class PeerManager;
class HealthMonitor;
class SyncRecovery;

class SelfHealingNode {
public:
    SelfHealingNode(Blockchain* blockchain, PeerManager* peerManager);

    // Periodic checks hooked into Network timers
    void checkPeerHeights();
    void kickStalledSync();
    void rescanDB();

    // Legacy wrappers (compat with CLI / tests)
    void monitorAndHeal();
    NodeHealthStatus manualHeal();
    void runPeriodicCheck(std::chrono::seconds interval);

    // --- future health modules (stubs) ---------------------------------
    void checkIdentityService();
    void checkSwapLiquidity();

private:
    std::unique_ptr<HealthMonitor> healthMonitor_;
    std::unique_ptr<SyncRecovery> syncRecovery_;
    Blockchain* blockchain_;
    PeerManager* peerManager_;
    std::size_t consecutiveFarBehind_;
    bool manualOverridePending_;

    NodeHealthStatus runHealthCheck(bool manualTrigger);
};

#endif // SELF_HEALING_NODE_H
