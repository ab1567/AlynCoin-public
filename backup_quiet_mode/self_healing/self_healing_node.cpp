#include "self_healing_node.h"
#include "health_monitor.h"
#include "sync_recovery.h"
#include "logger.h"

#include <thread>
#include <chrono>

SelfHealingNode::SelfHealingNode(Blockchain* blockchain, PeerManager* peerManager)
    : blockchain_(blockchain), peerManager_(peerManager) {
    healthMonitor_ = std::make_unique<HealthMonitor>(blockchain, peerManager);
    syncRecovery_ = std::make_unique<SyncRecovery>(blockchain, peerManager);
}

void SelfHealingNode::monitorAndHeal() {
    NodeHealthStatus status = healthMonitor_->checkHealth();
    healthMonitor_->logStatus(status);

    if (!healthMonitor_->shouldTriggerRecovery(status)) return;

    Logger::warn("🚨 Node health degraded. Initiating recovery...");

    if (!syncRecovery_->attemptRecovery(status.expectedTipHash)) {
        Logger::error("❌ Self-healing failed. Manual intervention may be required.");
    }
}

void SelfHealingNode::runPeriodicCheck(std::chrono::seconds interval) {
    while (true) {
        monitorAndHeal();
        std::this_thread::sleep_for(interval);
    }
}
