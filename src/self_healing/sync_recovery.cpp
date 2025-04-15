#include "sync_recovery.h"
#include "blockchain.h"
#include "peer_manager.h"
#include "block.h"
#include "logger.h"
#include "zk/winterfell_stark.h"
#include "zk/rust_bindings.h"

SyncRecovery::SyncRecovery(Blockchain* blockchain, PeerManager* peerManager)
    : blockchain_(blockchain), peerManager_(peerManager) {}

bool SyncRecovery::attemptRecovery(const std::string& expectedTipHash) {
    Logger::warn("[🔧 Recovery] Starting recovery process...");

    int rollbackHeight = findRollbackHeight(expectedTipHash);
    if (rollbackHeight < 0) {
        Logger::error("[❌ Recovery] Failed to find rollback point.");
        return false;
    }

    blockchain_->rollbackToHeight(rollbackHeight);
    Logger::info("[⏪ Recovery] Rolled back to block height " + std::to_string(rollbackHeight));

    if (!fetchAndApplyBlocksFromHeight(rollbackHeight + 1)) {
        Logger::error("[❌ Recovery] Failed to resync blocks from peers.");
        return false;
    }

    Logger::success("[✅ Recovery] Self-healing complete. Node resynced successfully.");
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
        if (!peerManager_->fetchBlockAtHeight(h, block)) {
            Logger::error("[❌ Fetch] Failed to retrieve block at height " + std::to_string(h));
            return false;
        }

        if (!validateBlock(block)) {
            Logger::error("[❌ Validate] Invalid block at height " + std::to_string(h));
            return false;
        }

        try {
            if (!blockchain_->addBlock(block)) {
                Logger::error("[❌ Add] Could not add block at height " + std::to_string(h));
                return false;
            }
        } catch (const std::exception& ex) {
            Logger::error("[❌ Exception] addBlock threw: " + std::string(ex.what()));
            return false;
        }

        Logger::info("[📥 Apply] Block " + std::to_string(h) + " applied successfully.");
    }

    return true;
}

bool SyncRecovery::validateBlock(const Block& block) {
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
