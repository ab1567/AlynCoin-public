#include "sync_recovery.h"
#include "blockchain.h"
#include "peer_manager.h"
#include "block.h"
#include "logger.h"
#include "network.h"
#include "zk/winterfell_stark.h"
#include "zk/rust_bindings.h"
#include "crypto_utils.h"
#include <thread>
#include <chrono>

SyncRecovery::SyncRecovery(Blockchain* blockchain, PeerManager* peerManager)
    : blockchain_(blockchain), peerManager_(peerManager) {}

bool SyncRecovery::markBlockInFlight(const std::string& hash) {
    Network* net = Network::getExistingInstance();
    bool reservedNetwork = false;
    if (net) {
        reservedNetwork = net->reserveBlockProcessing(hash);
        if (!reservedNetwork) {
            return false;
        }
    }

    std::lock_guard<std::mutex> lock(inflightMutex_);
    auto inserted = inflightBlocks_.insert(hash);
    if (!inserted.second) {
        if (reservedNetwork && net) {
            net->releaseBlockProcessing(hash);
        }
        return false;
    }
    return true;
}

void SyncRecovery::unmarkBlockInFlight(const std::string& hash) {
    {
        std::lock_guard<std::mutex> lock(inflightMutex_);
        inflightBlocks_.erase(hash);
    }

    if (auto net = Network::getExistingInstance()) {
        net->releaseBlockProcessing(hash);
    }
}

bool SyncRecovery::attemptRecovery(const std::string& expectedTipHash) {
    Logger::warn("[🔧 Recovery] Starting recovery process...");

    bool wasMining = false;
    if (blockchain_) {
        wasMining = blockchain_->isMiningActive();
        blockchain_->stopMining();
    }

    auto reportMiningPaused = [&]() {
        if (wasMining) {
            Logger::warn("[🔧 Recovery] Mining remains paused because recovery did not complete.");
        }
    };

    std::string rollbackHash = expectedTipHash;
    if (rollbackHash.empty() && peerManager_) {
        rollbackHash = peerManager_->getConsensusCommonHash(blockchain_->getHeight());
    }

    int rollbackHeight = -1;
    if (!rollbackHash.empty()) {
        rollbackHeight = findRollbackHeight(rollbackHash);
    }

    if (rollbackHeight < 0 && peerManager_) {
        std::string consensusHash = peerManager_->getConsensusCommonHash(blockchain_->getHeight());
        if (!consensusHash.empty() && consensusHash != rollbackHash) {
            Logger::warn("[🔧 Recovery] Falling back to consensus common hash "
                         "for rollback.");
            rollbackHash = consensusHash;
            rollbackHeight = findRollbackHeight(rollbackHash);
        }
    }

    if (rollbackHeight < 0) {
        Logger::error("[❌ Recovery] Failed to find rollback point.");

        Logger::warn(
            "[🧹 Recovery] No common ancestor found. Purging local data and "
            "requesting snapshot from peers...");

        if (blockchain_) {
            blockchain_->purgeDataForResync();
        }

        if (peerManager_) {
            auto peers = peerManager_->getConnectedPeerIds();
            if (!peers.empty()) {
                if (auto net = Network::getExistingInstance()) {
                    net->requestSnapshotSync(peers.front());
                } else {
                    Logger::warn("[🧹 Recovery] Network instance unavailable for snapshot request.");
                }
            } else {
                Logger::warn("[🧹 Recovery] No connected peers to request snapshot from.");
            }
        }

        reportMiningPaused();
        return false;
    }

    blockchain_->rollbackToHeight(rollbackHeight);
    Logger::info("[⏪ Recovery] Rolled back to block height " + std::to_string(rollbackHeight));

    if (!fetchAndApplyBlocksFromHeight(rollbackHeight + 1)) {
        Logger::error("[❌ Recovery] Failed to resync blocks from peers.");
        reportMiningPaused();
        return false;
    }

    Logger::success("[✅ Recovery] Self-healing complete. Node resynced successfully.");

    if (wasMining && blockchain_ && !blockchain_->resumeMiningFromLastConfig()) {
        Logger::warn("[🔧 Recovery] Mining was active before recovery but could not be resumed automatically.");
    }
    return true;
}

int SyncRecovery::findRollbackHeight(const std::string& validHash) {
    int currentHeight = blockchain_->getHeight();
    for (int h = currentHeight; h >= 0; --h) {
        std::string blockHash = blockchain_->getBlockHashAtHeight(h);
        if (blockHash == validHash) {
            Logger::info("[🔍 Match] Found rollback point at height " + std::to_string(h));
            return h;
        }
    }
    Logger::error("[❌ Match] No matching hash found in local chain.");
    return -1;
}

bool SyncRecovery::fetchAndApplyBlocksFromHeight(int startHeight) {
    if (startHeight != 0 && !blockchain_->hasBlocks()) {
        Logger::warn("[⚠️ Recovery] Local blockchain is empty. Forcing start height to 0.");
        startHeight = 0;
    }

    int networkHeight = peerManager_->getMedianNetworkHeight();
    Logger::info("[🌐 Sync] Attempting to apply blocks from height " +
                 std::to_string(startHeight) + " to " + std::to_string(networkHeight));

    for (int h = startHeight; h <= networkHeight; ++h) {
        Block block;
        int attempts = 0;
        // Transient network issues may temporarily prevent block downloads.
        // Increase the retry count so recovery is more resilient on
        // unstable links.
        const int maxAttempts = 5;
        while (attempts < maxAttempts) {
            if (peerManager_->fetchBlockAtHeight(h, block)) {
                break;
            }
            ++attempts;
            Logger::warn("[Fetch] Retry " + std::to_string(attempts) + "/" +
                         std::to_string(maxAttempts) +
                         " failed for height " + std::to_string(h));
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (attempts == maxAttempts) {
            Logger::error("[❌ Fetch] Failed to retrieve block at height " + std::to_string(h));
            return false;
        }

        const std::string blockHash = block.getHash();
        if (blockHash.empty()) {
            Logger::error("[❌ Validate] Received block with empty hash at height " + std::to_string(h));
            return false;
        }

        if (blockchain_->hasBlockHash(blockHash)) {
            Logger::info("[📥 Apply] Block " + std::to_string(h) + " already present. Skipping.");
            continue;
        }

        if (!markBlockInFlight(blockHash)) {
            Logger::info("[📥 Apply] Block " + blockHash + " is already being processed. Skipping duplicate download.");
            continue;
        }

        auto releaseInFlight = [&]() { unmarkBlockInFlight(blockHash); };

        if (!validateBlock(block)) {
            releaseInFlight();
            Logger::error("[❌ Validate] Invalid block at height " + std::to_string(h));
            return false;
        }

        if (blockchain_->hasBlockHash(blockHash)) {
            releaseInFlight();
            Logger::info("[📥 Apply] Block " + std::to_string(h) + " became available during validation. Skipping.");
            continue;
        }

        try {
            auto addRes = blockchain_->addBlock(block);
            if (addRes == Blockchain::BlockAddResult::Added) {
                releaseInFlight();
                Logger::info("[📥 Apply] Block " + std::to_string(h) + " applied successfully.");
                continue;
            }

            if (addRes == Blockchain::BlockAddResult::Duplicate ||
                addRes == Blockchain::BlockAddResult::Stale) {
                releaseInFlight();
                Logger::info("[📥 Apply] Block " + std::to_string(h) + " already processed via network path. Continuing.");
                continue;
            }

            releaseInFlight();
            Logger::error("[❌ Add] Could not add block at height " + std::to_string(h));
            return false;
        } catch (const std::exception& ex) {
            releaseInFlight();
            Logger::error("[❌ Exception] addBlock threw: " + std::string(ex.what()));
            return false;
        }
    }

    return true;
}

bool SyncRecovery::validateBlock(const Block& block) {
    if (blockchain_ && blockchain_->hasBlockHash(block.getHash())) {
        Logger::info("[🔁 Recovery] Block already exists locally. Skipping validation for " + block.getHash());
        return true;
    }

    if (!blockchain_->isValidNewBlock(block)) {
        Logger::error("[❌ Block] Structural validation failed for block.");
        return false;
    }

    // zk-STARK proof verification
    std::string blockHash = block.getHash();
    std::string proof(block.getZkProof().begin(), block.getZkProof().end());
    std::string expectedResult = blockHash.substr(0, 32);

    bool verified = verify_proof(proof.c_str(), blockHash.c_str(), expectedResult.c_str());
    if (!verified) {
        Logger::error("[❌ zkSTARK] Invalid proof for block: " + blockHash);
        return false;
    }

    return true;
}
