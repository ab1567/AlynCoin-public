#include "health_monitor.h"
#include "blockchain.h"
#include "peer_manager.h"
#include "logger.h"
#include "network.h"
#include "json/json.h"
#include "constants.h"

#include <iostream>
#include <sstream>
#include <iomanip>

HealthMonitor::HealthMonitor(Blockchain* blockchain, PeerManager* peerManager)
    : blockchain_(blockchain), peerManager_(peerManager), lastCheckTime_(std::chrono::steady_clock::now()) {}

NodeHealthStatus HealthMonitor::checkHealth() {
    NodeHealthStatus status;
    status.localHeight = blockchain_->getHeight();
    status.networkHeight = getNetworkHeight();
    status.localTipHash = getLocalTipHash();
    status.expectedTipHash = peerManager_->getConsensusTipHash(status.localHeight);
    status.connectedPeers = peerManager_->getPeerCount();
    auto localWorkBI = blockchain_->computeCumulativeDifficulty(blockchain_->getChain());
    uint64_t localWork = localWorkBI.convert_to<uint64_t>();
    uint64_t remoteWork = peerManager_->getMaxPeerWork();

    const uint64_t THRESHOLD = 1'000'000ULL;
    bool useHeightOnly = false;

    if (remoteWork > 0 && localWork > 0) {
        if (remoteWork / localWork > THRESHOLD ||
            localWork / remoteWork > THRESHOLD) {
            useHeightOnly = true;
        }
    }
    status.farBehind = false;

    if (remoteWork > localWork && status.networkHeight >= status.localHeight) {
        status.isHealthy = false;
        status.reason = "Out of sync";
        return status;
    } else if (remoteWork > localWork) {
        status.isHealthy = true;
        status.reason = "Local height higher";
    }

    bool stronger = useHeightOnly
                    ? (status.networkHeight > status.localHeight)
                    : (remoteWork > localWork);

    if (!stronger) {
        status.isHealthy = true;
        status.reason = "Local chain heavier";
    } else if (status.localHeight > status.networkHeight + 3) {
        Logger::warn("[🩺 NODE HEALTH] ⚠ Out of sync – forcing re-probe");
        if (auto net = Network::getExistingInstance()) {
            alyncoin::net::Frame fr; fr.mutable_height_req();
            net->broadcastFrame(fr);
        }
        status.isHealthy = false;
        status.reason = "Out of sync";
        return status;
    } else {
        status.isHealthy = true;
        status.reason = "Healthy";
    }

    if (status.localHeight + 5 < status.networkHeight) {
        status.isHealthy = false;
        status.reason = "Node is behind the network";
    } else if (stronger && status.localTipHash != status.expectedTipHash) {
        status.isHealthy = false;
        status.reason = "Tip hash mismatch with stronger chain";
    } else if (status.localTipHash != status.expectedTipHash) {
        status.isHealthy = true;
        status.reason = "Tip mismatch but we are heavier";
    }
    if (status.networkHeight > 0 &&
        status.networkHeight > status.localHeight + DESYNC_THRESHOLD) {
        status.farBehind = true;
        status.isHealthy = false;
        status.reason = "Node far behind";
    }

    return status;
}

void HealthMonitor::logStatus(const NodeHealthStatus& status) {
    std::ostringstream log;
    log << "[🩺 NODE HEALTH] "
        << (status.isHealthy ? "✅ Healthy" : "⚠️ Unhealthy") << " - Reason: " << status.reason << "\n"
        << "  • Local Height: " << status.localHeight << "\n"
        << "  • Network Height: " << status.networkHeight << "\n"
        << "  • Peers: " << status.connectedPeers << "\n"
        << "  • Local Work: " << blockchain_->computeCumulativeDifficulty(blockchain_->getChain()).convert_to<uint64_t>() << "\n"
        << "  • Remote Work: " << peerManager_->getMaxPeerWork() << "\n"
        << "  • Local Tip Hash: " << status.localTipHash.substr(0, 10) << "...\n"
        << "  • Expected Tip Hash: " << status.expectedTipHash.substr(0, 10) << "...";

    if (status.farBehind) {
        log << "\n  • Desync Gap: " << (status.networkHeight - status.localHeight);
    }

    Logger::info(log.str());
}

bool HealthMonitor::shouldTriggerRecovery(const NodeHealthStatus& status) {
    return !status.isHealthy || status.farBehind;
}

std::string HealthMonitor::getLocalTipHash() const {
    return blockchain_->getLatestBlockHash();
}

std::string HealthMonitor::getNetworkTipHash() const {
    return peerManager_->getMajorityTipHash();
}

uint64_t HealthMonitor::getNetworkHeight() const {
    return peerManager_->getMedianNetworkHeight();
}
