#include "self_healing_node.h"
#include "health_monitor.h"
#include "sync_recovery.h"
#include "logger.h"
#include "network.h"
#include <thread>
#include <chrono>
#include <vector>

SelfHealingNode::SelfHealingNode(Blockchain* blockchain, PeerManager* peerManager)
    : blockchain_(blockchain), peerManager_(peerManager), consecutiveFarBehind_(0),
      manualOverridePending_(false) {
    healthMonitor_ = std::make_unique<HealthMonitor>(blockchain, peerManager);
    syncRecovery_ = std::make_unique<SyncRecovery>(blockchain, peerManager);
}

NodeHealthStatus SelfHealingNode::runHealthCheck(bool manualTrigger) {
    NodeHealthStatus status{};

    if (!healthMonitor_) {
        Logger::error("❌ [SelfHealer] Health monitor unavailable.");
        status.isHealthy = false;
        status.reason = "Health monitor unavailable";
        return status;
    }

    if (!blockchain_) {
        Logger::error("❌ [SelfHealer] Blockchain instance unavailable.");
        status.isHealthy = false;
        status.reason = "Blockchain unavailable";
        return status;
    }

    if (!peerManager_) {
        Logger::warn("⚠️ [SelfHealer] Peer manager unavailable; cannot evaluate peers.");
        status.isHealthy = false;
        status.reason = "Peer manager unavailable";
        return status;
    }

    if (auto net = Network::getExistingInstance()) {
        alyncoin::net::Frame fr;
        fr.mutable_height_req();
        net->broadcastFrame(fr);
    }

    status = healthMonitor_->checkHealth();
    healthMonitor_->logStatus(status);

    auto ensureManualKick = [this, manualTrigger]() {
        if (!manualTrigger)
            return;
        Logger::info("🩺 [SelfHealer] Manual hard sync requested. Forcing peer re-sync probes...");
        kickStalledSync();
    };

    Network *netPtr = Network::getExistingInstance();
    const bool snapshotActive = netPtr && netPtr->isSnapshotActive();

    if (manualTrigger)
        manualOverridePending_ = true;

    if (snapshotActive && !manualTrigger) {
        if (!manualOverridePending_) {
            Logger::info("🩺 [SelfHealer] Snapshot transfer in progress; deferring recovery.");
            consecutiveFarBehind_ = 0;
        } else {
            Logger::info("🩺 [SelfHealer] Snapshot active; preserving manual override confirmations.");
        }
        ensureManualKick();
        return status;
    }

    const bool freshBootstrap = !blockchain_->hasBlocks() &&
                                status.localHeight == 0 &&
                                status.networkHeight > 0;

    if (freshBootstrap) {
        Logger::info(
            "🩺 [SelfHealer] Initial bootstrap detected; deferring recovery while "
            "waiting for snapshot/tail sync.");
        consecutiveFarBehind_ = 0;
        manualOverridePending_ = false;
        if (!snapshotActive && netPtr) {
            Logger::info(
                "🩺 [SelfHealer] No snapshot active yet — nudging network sync.");
            netPtr->autoSyncIfBehind();
            netPtr->intelligentSync();
        }
        ensureManualKick();
        return status;
    }

    constexpr std::size_t FAR_BEHIND_CONFIRMATIONS = 3;

    if (status.farBehind) {
        ++consecutiveFarBehind_;
        Logger::warn(
            "🚨 Node far behind (" + std::to_string(consecutiveFarBehind_) + "/" +
            std::to_string(FAR_BEHIND_CONFIRMATIONS) +
            "). Waiting for confirmation before purging local data...");

        if (consecutiveFarBehind_ < FAR_BEHIND_CONFIRMATIONS) {
            ensureManualKick();
            return status;
        }

        Logger::warn("🚨 Node far behind confirmed. Purging local data and requesting snapshot...");
        consecutiveFarBehind_ = 0;
        manualOverridePending_ = false;

        blockchain_->purgeDataForResync();
        std::vector<std::string> peerIds = peerManager_ ? peerManager_->getConnectedPeerIds() : std::vector<std::string>{};
        if (!peerIds.empty()) {
            if (auto net = Network::getExistingInstance()) {
                net->requestSnapshotSync(peerIds.front());
            }
        } else {
            Logger::warn("⚠️ [SelfHealer] No peers available to request snapshot from.");
        }
        ensureManualKick();
        return status;
    }

    consecutiveFarBehind_ = 0;
    manualOverridePending_ = false;

    if (!healthMonitor_->shouldTriggerRecovery(status)) {
        ensureManualKick();
        return status;
    }

    Logger::warn("🚨 Node health degraded. Initiating recovery...");

    if (!syncRecovery_->attemptRecovery(status.expectedTipHash)) {
        Logger::error("❌ Self-healing failed. Manual intervention may be required.");
    }

    ensureManualKick();
    return status;
}

void SelfHealingNode::checkPeerHeights() {
    runHealthCheck(false);
}

void SelfHealingNode::kickStalledSync() {
    if (auto net = Network::getExistingInstance()) {
        net->autoSyncIfBehind();
        net->intelligentSync();
    }
}

void SelfHealingNode::rescanDB() {
    Logger::info("[SelfHealer] Rescanning blockchain DB...");
    blockchain_->reloadBlockchainState();
    blockchain_->validateChainContinuity();
}

void SelfHealingNode::checkIdentityService() {}

void SelfHealingNode::checkSwapLiquidity() {}

// ---------------------------------------------------------------------
// Legacy wrappers used by older CLI paths
void SelfHealingNode::monitorAndHeal() {
    runHealthCheck(false);
}

NodeHealthStatus SelfHealingNode::manualHeal() {
    return runHealthCheck(true);
}

void SelfHealingNode::runPeriodicCheck(std::chrono::seconds interval) {
    while (true) {
        checkPeerHeights();
        std::this_thread::sleep_for(interval);
    }
}
