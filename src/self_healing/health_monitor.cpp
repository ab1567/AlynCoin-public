#include "health_monitor.h"
#include "blockchain.h"
#include "peer_manager.h"
#include "logger.h"
#include "network.h"
#include "json/json.h"
#include "constants.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>

HealthMonitor::HealthMonitor(Blockchain* blockchain, PeerManager* peerManager)
    : blockchain_(blockchain),
      peerManager_(peerManager),
      lastCheckTime_(std::chrono::steady_clock::now()),
      lastPeerDialAttempt_(std::chrono::steady_clock::time_point::min()) {}

NodeHealthStatus HealthMonitor::checkHealth() {
    NodeHealthStatus status;
    status.localHeight = blockchain_->getHeight();
    status.networkHeight = getNetworkHeight();
    status.localTipHash = getLocalTipHash();
    status.consensusCommonHash =
        peerManager_->getConsensusCommonHash(status.localHeight);
    status.expectedTipHash =
        peerManager_->getConsensusTipHash(status.localHeight);
    if (status.expectedTipHash.empty())
        status.expectedTipHash = status.consensusCommonHash;
    status.connectedPeers = peerManager_->getPeerCount();
    status.networkConnectedPeers = status.connectedPeers;
    size_t trackedEndpoints = status.connectedPeers;
    size_t discoveredCount = 0;
    if (auto net = Network::getExistingInstance()) {
        trackedEndpoints = net->getTrackedEndpointCount();
        status.networkConnectedPeers = std::max(status.networkConnectedPeers, trackedEndpoints);
        if (trackedEndpoints == 0) {
            auto discovered = net->discoverPeers();
            discoveredCount = discovered.size();
            status.networkConnectedPeers = std::max(status.networkConnectedPeers, discoveredCount);
        }

        bool shouldDial = status.networkConnectedPeers > status.connectedPeers && status.networkConnectedPeers > 0;
        if (!shouldDial && discoveredCount > status.connectedPeers && discoveredCount > 0) {
            shouldDial = true;
        }

        if (shouldDial) {
            auto now = std::chrono::steady_clock::now();
            if (now - lastPeerDialAttempt_ > std::chrono::seconds(30)) {
                net->connectToDiscoveredPeers();
                lastPeerDialAttempt_ = now;
            }
        }
    }
    auto localWorkBI = blockchain_->computeCumulativeDifficulty(blockchain_->getChain());
    uint64_t localWork = localWorkBI.convert_to<uint64_t>();
    uint64_t remoteWork = peerManager_->getMaxPeerWork();

    status.localWork = localWork;
    status.remoteWork = remoteWork;

    const uint64_t THRESHOLD = 1'000'000ULL;
    bool useHeightOnly = false;

    if (remoteWork > 0 && localWork > 0) {
        if (remoteWork / localWork > THRESHOLD ||
            localWork / remoteWork > THRESHOLD) {
            useHeightOnly = true;
        }
    }

    status.remoteAhead = status.networkHeight > status.localHeight;
    status.heightGap = status.remoteAhead
                       ? (status.networkHeight - status.localHeight)
                       : 0;
    status.tipMismatch = !status.expectedTipHash.empty() &&
                         status.localTipHash != status.expectedTipHash;

    bool stronger = useHeightOnly
                    ? status.remoteAhead
                    : (remoteWork > localWork);
    status.remoteStronger = stronger;
    status.farBehind = false;

    status.isHealthy = true;
    status.reason = "Local chain heavier";

    if (stronger) {
        status.isHealthy = false;
        if (status.heightGap > 1) {
            status.reason = "Out of sync";
        } else if (status.tipMismatch) {
            status.reason = "Tip hash mismatch with stronger chain";
        } else if (status.heightGap == 1) {
            status.reason = "Catching up to stronger chain";
        } else {
            status.reason = "Remote chain has more work";
        }
    } else {
        if (status.tipMismatch && status.remoteAhead) {
            status.reason = "Tip mismatch but we are heavier";
        } else if (status.remoteAhead) {
            status.reason = "Local height higher";
        }
    }

    if (!status.remoteStronger && status.localHeight > status.networkHeight + 3) {
        Logger::warn("[🩺 NODE HEALTH] ⚠ Out of sync – forcing re-probe");
        if (auto net = Network::getExistingInstance()) {
            alyncoin::net::Frame fr; fr.mutable_height_req();
            net->broadcastFrame(fr);
        }
        status.isHealthy = false;
        status.reason = "Out of sync";
        return status;
    }

    if (status.localHeight + 5 < status.networkHeight) {
        status.isHealthy = false;
        status.reason = "Node is behind the network";
    } else if (status.remoteStronger && status.tipMismatch) {
        status.isHealthy = false;
        status.reason = "Tip hash mismatch with stronger chain";
    } else if (status.tipMismatch) {
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
        << "  • Peers: local=" << status.connectedPeers
        << " / network=" << status.networkConnectedPeers << "\n"
        << "  • Local Work: " << status.localWork << "\n"
        << "  • Remote Work: " << status.remoteWork << "\n"
        << "  • Height Gap: " << status.heightGap << "\n"
        << "  • Local Tip Hash: " << status.localTipHash.substr(0, 10) << "...\n"
        << "  • Expected Tip Hash: " << status.expectedTipHash.substr(0, 10) << "...";

    if (!status.consensusCommonHash.empty()) {
        log << "\n  • Consensus Common Hash: "
            << status.consensusCommonHash.substr(0, 10) << "...";
    }

    log << "\n  • Tip Mismatch: " << (status.tipMismatch ? "yes" : "no");
    log << "\n  • Remote Stronger: " << (status.remoteStronger ? "yes" : "no");

    if (status.farBehind) {
        log << "\n  • Desync Gap: " << (status.networkHeight - status.localHeight);
    }

    Logger::info(log.str());
}

bool HealthMonitor::shouldTriggerRecovery(const NodeHealthStatus& status) {
    if (status.farBehind) {
        return true;
    }

    if (!status.isHealthy) {
        if (status.heightGap > 1) {
            return true;
        }
        if (status.remoteStronger && status.tipMismatch) {
            return true;
        }
    }

    return false;
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
