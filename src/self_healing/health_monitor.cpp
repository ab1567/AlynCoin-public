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
    status.expectedTipHash = getNetworkTipHash();
    status.connectedPeers = peerManager_->getPeerCount();
    status.farBehind = false;

    if (status.networkHeight == 0 ||
        status.localHeight > status.networkHeight + 3) {
        Logger::warn("[🩺 NODE HEALTH] ⚠ Out of sync – forcing re-probe");
        if (auto net = Network::getExistingInstance()) {
            Json::Value j; j["type"] = "height_request";
            Json::StreamWriterBuilder b; b["indentation"] = "";
            net->broadcastRaw("ALYN|" + Json::writeString(b, j) + "\n");
        }
        status.isHealthy = false;
        status.reason = "Out of sync";
        return status;
    }

    status.isHealthy = true;
    status.reason = "Healthy";

    if (status.connectedPeers == 0) {
        status.isHealthy = false;
        status.reason = "No connected peers";
    } else if (status.localHeight + 5 < status.networkHeight) {
        status.isHealthy = false;
        status.reason = "Node is behind the network";
    } else if (status.localTipHash != status.expectedTipHash && status.networkHeight - status.localHeight < 10) {
        status.isHealthy = false;
        status.reason = "Tip hash mismatch with peers";
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
